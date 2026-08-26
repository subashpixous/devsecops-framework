"""Command line entrypoint.

    python -m framework.cli detect --workspace .
    python -m framework.cli tools
    python -m framework.cli run --workspace . --output security-results

`run` executes the approved pipeline:

    detect -> collect (per stage) -> normalize -> aggregate (lifecycle)
           -> evaluate -> report

Exit codes:
    0  reports generated. THE DEFAULT, whatever was found.
    2  SECURITY = FAILED           and --fail-on security was requested
    3  SECURITY = NOT_VERIFIED     and --fail-on security was requested
    4  the framework itself failed to produce a complete report
    5  DEPLOYMENT DECISION is not READY  and --fail-on decision was requested
    6  EVIDENCE = UNTRUSTWORTHY    and --fail-on evidence was requested

A SECURITY FINDING DOES NOT STOP THIS PROGRAM. `--fail-on` defaults to `never`,
so discovering a vulnerability produces exit 0 and the run continues to
collection, normalisation, reporting, readiness and evidence. The finding is in
the report; terminating the pipeline would only make it less visible.

What CAN still stop it is the framework failing at its own job. Exit code 4
exists so a broken framework is loud, and it never converts into a passing
security verdict. Exit 6 exists so a self-contradictory evidence set can be
made loud too, for a caller that wants it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .collectors.base import ScannerResult
from .core.categories import PIPELINE_STAGES, SECURITY_FAILED, SECURITY_NOT_VERIFIED, SECURITY_PASS
from .core.context import RunContext
from .core.lifecycle import apply_lifecycle, load_baseline, load_exceptions
from .core.policy import Policy
from .core.correlation import correlate
from .core.evidence import build_manifest as build_evidence_manifest, write_manifest
from .core.prioritization import enrich_findings
from .core.coverage import build_manifest
from .core import readiness as readiness_model
from .core.registry import (
    CATEGORY_BY_KEY,
    import_failures,
    load_builtin_scanners,
    registered_scanners,
    scanners_for_phase,
)
from .core.schema import Finding
from .core.status_engine import StatusEngine
from .core.toolrunner import tool_available, tool_version
from .detect.detector import detect
from .report.csv_writer import write_csv
from .report.json_writer import build_report, write_json, write_normalized_findings
from .report.markdown_writer import write_markdown
from .report.pdf_writer import PdfGenerationError, write_pdf
from .report.sarif_writer import write_sarif

EXIT_OK = 0
EXIT_SECURITY_FAILED = 2
EXIT_SECURITY_NOT_VERIFIED = 3
EXIT_FRAMEWORK_ERROR = 4
EXIT_NOT_DEPLOYABLE = 5
EXIT_EVIDENCE_UNTRUSTWORTHY = 6

# What a caller may ask this program to fail on. `never` is the default and the
# recommended setting: the pipeline's job is to finish and publish evidence, and
# the deployment decision is a separate output that a deployment job gates on.
FAIL_ON_NEVER = "never"
FAIL_ON_EVIDENCE = "evidence"
FAIL_ON_DECISION = "decision"
FAIL_ON_SECURITY = "security"
FAIL_ON_CHOICES = (FAIL_ON_NEVER, FAIL_ON_EVIDENCE, FAIL_ON_DECISION, FAIL_ON_SECURITY)

# External binaries the framework can drive, for the `tools` subcommand.
KNOWN_BINARIES = (
    ("semgrep", ("--version",)), ("opengrep", ("--version",)), ("gitleaks", ("version",)),
    ("trivy", ("--version",)), ("checkov", ("--version",)), ("nuclei", ("-version",)),
    ("cosign", ("version",)), ("prowler", ("--version",)), ("aws", ("--version",)),
    ("docker", ("--version",)), ("zap-baseline.py", ("-h",)), ("42c-ci-scan", ("--version",)),
)


def _log(message: str) -> None:
    print("[devsecops-framework] %s" % message, flush=True)


def _csv(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", default=os.environ.get("GITHUB_WORKSPACE", "."))
    parser.add_argument("--output", default="security-results")
    parser.add_argument("--project-name", default="")
    parser.add_argument("--environment", default="")
    parser.add_argument("--deployment-target", default="")
    parser.add_argument("--deployed-url", default="")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devsecops-framework", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    detect_parser = sub.add_parser("detect", help="Emit capabilities.json only.")
    _add_common(detect_parser)

    sub.add_parser("tools", help="Report which external scanners are available.")

    run_parser = sub.add_parser("run", help="Run the pipeline.")
    _add_common(run_parser)
    run_parser.add_argument("--policy", default="")
    run_parser.add_argument("--active-phase", type=int, default=0)
    run_parser.add_argument(
        "--stage", default="",
        help="Comma-separated pipeline stages to execute (%s). Default: all." % ",".join(PIPELINE_STAGES),
    )
    run_parser.add_argument("--sonar-project-key", default="")
    run_parser.add_argument(
        "--max-analysis-age-days", type=int, default=0,
        help="How old a SonarQube analysis may be before its results are reported as STALE "
             "when no revision is available for comparison (0 = framework default, 7 days). "
             "A revision match is authoritative at any age; a mismatch is stale at any age.",
    )
    run_parser.add_argument("--build-status", default="")
    run_parser.add_argument("--deployment-status", default="")
    run_parser.add_argument(
        "--test-status", default="",
        help="Unit-test result reported by the caller (pass/fail/skipped). Never inferred. "
             "Left unreported it becomes a readiness dimension in state NOT_REPORTED, which "
             "scores nothing and lowers assurance -- it is never read as a pass.",
    )
    run_parser.add_argument(
        "--test-coverage-percent", default="",
        help="Test-coverage percentage reported by the caller (0-100). Never inferred. "
             "Anything unparseable is treated as NOT_REPORTED rather than as zero.",
    )
    run_parser.add_argument("--images", default="", help="Comma-separated image refs for image/SBOM/signature scans.")
    run_parser.add_argument("--cloud", default="", help="Cloud provider for posture scanning (aws|azure|gcp).")
    run_parser.add_argument("--aws-region", default="")
    run_parser.add_argument("--zap-mode", default="baseline", choices=("baseline", "full"))
    run_parser.add_argument("--bundle-dirs", default="", help="Comma-separated built frontend directories.")
    run_parser.add_argument("--openapi-files", default="", help="Comma-separated OpenAPI spec paths.")
    run_parser.add_argument("--baseline", default="", help="Previous normalized-findings.json for lifecycle diffing.")
    run_parser.add_argument("--exceptions", default="", help="Exceptions/accepted-risk file (YAML or JSON).")
    run_parser.add_argument(
        "--fail-on", default=FAIL_ON_NEVER, choices=FAIL_ON_CHOICES,
        help="Which condition makes this program exit non-zero. "
             "never (default): only a framework failure does. "
             "evidence: also when the evidence set contradicts itself. "
             "decision: also when the deployment decision is not READY. "
             "security: also when SECURITY is not PASS -- the legacy behaviour. "
             "A security FINDING never stops the run under any setting; these select "
             "which computed VERDICT is mirrored into the exit status.",
    )
    run_parser.add_argument(
        "--fail-on-security", action="store_true",
        help="Deprecated alias for --fail-on security. Retained so existing callers keep "
             "working unchanged.",
    )
    run_parser.add_argument(
        "--max-table-rows", type=int, default=0,
        help="Findings table rows in report.md / the PDF (0 = writer default). "
             "findings.csv is never truncated.",
    )
    run_parser.add_argument(
        "--max-detailed-findings", type=int, default=0,
        help="Detailed finding entries in report.md / the PDF (0 = writer default).",
    )
    run_parser.add_argument(
        "--include-dependencies", action="store_true",
        help="Also run static analysis over vendored dependency source (vendor/, node_modules/). "
             "Off by default; either way the choice is recorded in the coverage manifest.",
    )
    run_parser.add_argument(
        "--no-enrichment", action="store_true",
        help="Skip EPSS and CISA KEV lookups entirely. Both are third-party network calls; "
             "without them findings carry no exploitability context and the report says so.",
    )
    run_parser.add_argument(
        "--epss-file", default="",
        help="Local EPSS JSON (offline/air-gapped runners) instead of the FIRST API.",
    )
    run_parser.add_argument(
        "--kev-file", default="",
        help="Local CISA KEV catalogue JSON instead of the live feed.",
    )
    run_parser.add_argument(
        "--enrichment-timeout", type=int, default=15,
        help="Seconds to wait for each enrichment source before giving up (default 15).",
    )
    run_parser.add_argument("--sonar-payload", default="", help="Self-test only: load a captured payload.")
    return parser


def _capability_overrides(args: argparse.Namespace) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    if getattr(args, "deployment_target", ""):
        overrides["deployment_target"] = args.deployment_target
    if getattr(args, "deployed_url", ""):
        overrides["deployed_url"] = args.deployed_url
    if getattr(args, "cloud", ""):
        overrides["cloud"] = args.cloud
    return overrides


def command_detect(args: argparse.Namespace) -> int:
    capabilities = detect(args.workspace, _capability_overrides(args))
    os.makedirs(args.output, exist_ok=True)
    path = os.path.join(args.output, "capabilities.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(capabilities, handle, indent=2)
        handle.write("\n")
    _log("capabilities written to %s" % path)
    print(json.dumps(capabilities, indent=2))
    return EXIT_OK


def command_tools(_args: argparse.Namespace) -> int:
    load_builtin_scanners()
    print("Registered scanners: %d" % len(registered_scanners()))
    for registration in registered_scanners():
        print("  %-24s -> %-24s (phase %d)" % (registration.tool, registration.category_key, registration.phase))
    print("\nExternal binaries:")
    for binary, version_args in KNOWN_BINARIES:
        available = tool_available(binary)
        version = tool_version(binary, version_args) if available else ""
        print("  %-18s %-14s %s" % (binary, "AVAILABLE" if available else "MISSING", version[:60]))
    failures = import_failures()
    if failures:
        print("\nCollector import failures:")
        for name, error in failures.items():
            print("  %-18s %s" % (name, error))
    return EXIT_OK


def _collect(
    args: argparse.Namespace,
    context: RunContext,
    policy: Policy,
    capabilities: Dict[str, Any],
    stages: Sequence[str],
) -> tuple:
    """Run every registered scanner whose category is in scope for this run."""
    load_builtin_scanners()
    registrations = scanners_for_phase(policy.active_phase)

    # Shared kwarg bag; each collector filters it to what it understands.
    kwargs: Dict[str, Any] = {
        "workspace": args.workspace,
        "branch": context.branch,
        # The commit under validation. SonarQube is the one scanner whose results
        # are produced elsewhere, so it needs this to prove the analysis it read
        # describes THIS code rather than whatever was analysed last.
        "commit": context.commit,
        "max_analysis_age_days": args.max_analysis_age_days,
        "project_key": args.sonar_project_key or None,
        "images": _csv(args.images),
        "deployed_url": context.deployed_url,
        "target_url": context.deployed_url,
        "cloud": args.cloud or capabilities.get("cloud") or "",
        "aws_region": args.aws_region,
        "zap_mode": args.zap_mode,
        "bundle_dirs": _csv(args.bundle_dirs),
        "openapi_files": _csv(args.openapi_files) or list(capabilities.get("openapi_spec_files") or []),
        "output_dir": args.output,
        # Detected languages drive per-tool path policy: which vendored directory
        # is dependency code, and which rule packs a SAST engine should load.
        "languages": list(capabilities.get("languages") or []),
        "web_server_config_files": list(capabilities.get("web_server_config_files") or []),
        "include_dependencies": bool(getattr(args, "include_dependencies", False)),
    }

    results: List[ScannerResult] = []
    findings: List[Finding] = []
    quality_gate: Dict[str, Any] = {}

    for registration in registrations:
        category = CATEGORY_BY_KEY.get(registration.category_key)
        if category is None:
            continue
        if category.stage not in stages:
            continue

        _log("collecting: %s (%s / %s)" % (registration.tool, registration.category_key, category.stage))
        try:
            collector = registration.collector_factory(**kwargs)
            result = collector.collect()
        except Exception as exc:  # noqa: BLE001 - a collector must never take down the run
            result = ScannerResult(tool=registration.tool, category_key=registration.category_key)
            result.fail("collector raised an unexpected exception: %s" % exc).finish()
            _log("  collector %s raised: %s" % (registration.tool, exc))

        if args.sonar_payload and registration.tool == "sonarqube":
            try:
                with open(args.sonar_payload, "r", encoding="utf-8") as handle:
                    result.payload = json.load(handle)
                result.metadata["payload_source"] = "local file -- NOT a live scan"
                result.replay()
                result.succeed()
                result.warnings.append(
                    "Results were loaded from a local payload file rather than a live server. "
                    "This run does not prove connectivity to the analysis server."
                )
            except (OSError, ValueError) as exc:
                result.fail("could not load payload override: %s" % exc)

        result.write_raw(args.output, "%s.json" % registration.tool.replace("/", "-"))
        results.append(result)

        try:
            adapter = registration.adapter_factory()
            scanner_findings = adapter.normalize(result, context)
        except Exception as exc:  # noqa: BLE001
            result.fail("adapter raised an unexpected exception: %s" % exc)
            scanner_findings = []
            _log("  adapter %s raised: %s" % (registration.tool, exc))
        findings.extend(scanner_findings)

        try:
            gate = adapter.summarize_gate(result)
            if gate and (gate.get("status") != "UNKNOWN" or not quality_gate):
                quality_gate = gate
        except Exception:  # noqa: BLE001
            pass

        _log(
            "  -> status=%s findings=%d errors=%d warnings=%d"
            % (result.status, len(scanner_findings), len(result.errors), len(result.warnings))
        )

    return results, findings, quality_gate


def _write_step_summary(report: Dict[str, Any]) -> None:
    """The management view, rendered where nobody has to download anything."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    status = report["status"]
    ready = report.get("readiness") or {}
    severities = report["findings"].get("security_severity_breakdown") or {}
    lifecycle = (report.get("lifecycle") or {}).get("counts") or {}

    lines = [
        "## Deployment Readiness Summary",
        "",
        "| | |",
        "|---|---|",
        "| Application | %s |" % report["project"]["project_name"],
        "| Commit | `%s` |" % report["project"]["commit_short"],
        "| **Deployment decision** | **`%s`** |" % ready.get("decision", "UNKNOWN"),
        "| Readiness | **%s%%** |" % ready.get("readiness_percent", 0.0),
        "| Assurance (how much was measured) | **%s%%** |" % ready.get("assurance_percent", 0.0),
        "| Evidence | `%s` |" % ready.get("evidence_status", "UNTRUSTWORTHY"),
        "| Deployment permitted by this run | **%s** |"
        % ("YES" if ready.get("deployment_permitted") else "NO"),
        "",
        ready.get("statement", ""),
        "",
        "### Findings",
        "",
        "| CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |",
        "|---|---|---|---|---|",
        "| %d | %d | %d | %d | %d |"
        % (severities.get("CRITICAL", 0), severities.get("HIGH", 0), severities.get("MEDIUM", 0),
           severities.get("LOW", 0), severities.get("UNKNOWN", 0)),
        "",
        "%d open finding(s) in total (new %s / existing %s / fixed %s). Every one of them is "
        "in the attached report; none was suppressed to keep this pipeline running."
        % (report["findings"]["open"], lifecycle.get("new", "?"),
           lifecycle.get("existing", "?"), lifecycle.get("fixed", "?")),
        "",
    ]

    blockers = ready.get("blockers") or []
    if blockers:
        lines.append("### Blockers")
        lines.append("")
        for index, blocker in enumerate(blockers, 1):
            lines.append("%d. **%s** -- %s" % (index, blocker["title"], blocker["reason"]))
        lines.append("")

    unknowns = ready.get("unknowns") or []
    if unknowns:
        lines.append("### Not established (these are NOT passes)")
        lines.append("")
        for unknown in unknowns[:10]:
            lines.append("- **%s** is `%s`" % (unknown["title"], unknown["state"]))
        if len(unknowns) > 10:
            lines.append("- ...and %d more, listed in full in the report." % (len(unknowns) - 10))
        lines.append("")

    lines.extend([
        "### Validation detail",
        "",
        "| Result | Status |",
        "|---|---|",
        "| Pipeline | `%s` |" % (report.get("pipeline") or {}).get("status", "UNKNOWN"),
        "| Build | `%s` |" % status["build"],
        "| Deployment | `%s` |" % status["deployment"],
        "| **Security** | **`%s`** |" % status["security"],
        "| **Runtime security** | **`%s`** |" % status["runtime_security"],
        "",
        "Scope: `%s`" % status["verdict_scope"],
        "",
        "> A deployment result never implies a security result, and a security finding does "
        "not by itself stop this pipeline.",
        "",
    ])
    if not status["coverage_complete"]:
        lines.append("> **Partial coverage.** Categories marked NOT_IMPLEMENTED / NOT_VERIFIED were not tested.")
        lines.append("")
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except OSError as exc:
        _log("could not write job summary: %s" % exc)


def _write_outputs(report: Dict[str, Any]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    status = report["status"]
    lifecycle = (report.get("lifecycle") or {}).get("counts") or {}
    try:
        with open(output_path, "a", encoding="utf-8") as handle:
            handle.write("build_status=%s\n" % status["build"])
            handle.write("deployment_status=%s\n" % status["deployment"])
            handle.write("security_status=%s\n" % status["security"])
            handle.write("runtime_security_status=%s\n" % status["runtime_security"])
            handle.write("open_findings=%d\n" % report["findings"]["open"])
            handle.write("new_findings=%s\n" % lifecycle.get("new", 0))
            handle.write("fixed_findings=%s\n" % lifecycle.get("fixed", 0))
            handle.write("coverage_complete=%s\n" % str(status["coverage_complete"]).lower())
            # The outputs a deployment job should gate on. They are deliberately
            # separate from security_status: a caller that wants to know "may I
            # deploy" must not have to re-derive it from a security verdict.
            ready = report.get("readiness") or {}
            handle.write("pipeline_status=%s\n" % (report.get("pipeline") or {}).get("status", ""))
            handle.write("evidence_status=%s\n" % ready.get("evidence_status", ""))
            handle.write("deployment_decision=%s\n" % ready.get("decision", ""))
            handle.write("deployment_permitted=%s\n"
                         % str(bool(ready.get("deployment_permitted"))).lower())
            handle.write("readiness_percent=%s\n" % ready.get("readiness_percent", 0.0))
            handle.write("readiness_assurance_percent=%s\n" % ready.get("assurance_percent", 0.0))
            severities = report["findings"].get("security_severity_breakdown") or {}
            handle.write("critical_findings=%d\n" % severities.get("CRITICAL", 0))
            handle.write("high_findings=%d\n" % severities.get("HIGH", 0))
    except OSError as exc:
        _log("could not write step outputs: %s" % exc)


def command_run(args: argparse.Namespace) -> int:  # noqa: C901 - linear orchestration
    os.makedirs(args.output, exist_ok=True)

    policy = Policy.load(args.policy or None)
    if args.active_phase:
        policy.active_phase = args.active_phase

    stages = [s.upper() for s in _csv(args.stage)] or list(PIPELINE_STAGES)
    unknown = [s for s in stages if s not in PIPELINE_STAGES]
    if unknown:
        _log("ERROR: unknown stage(s) %s; valid stages are %s" % (unknown, list(PIPELINE_STAGES)))
        return EXIT_FRAMEWORK_ERROR

    _log("policy=%s active_phase=%d required=%s" % (policy.name, policy.active_phase, policy.required_categories))
    _log("stages=%s" % ",".join(stages))

    capabilities = detect(args.workspace, _capability_overrides(args))
    with open(os.path.join(args.output, "capabilities.json"), "w", encoding="utf-8") as handle:
        json.dump(capabilities, handle, indent=2)
        handle.write("\n")
    _log(
        "detected languages=%s docker=%s iac=%s k8s=%s openapi=%s frontend=%s backend=%s"
        % (capabilities["languages"], capabilities["docker"], capabilities["iac"],
           capabilities["kubernetes"], capabilities["openapi"],
           capabilities["frontend"], capabilities["backend"])
    )

    context = RunContext.from_environment(
        {
            "project_name": args.project_name,
            "environment": args.environment,
            "deployment_target": args.deployment_target or capabilities.get("deployment_target") or "",
            "deployed_url": args.deployed_url or capabilities.get("deployed_url") or "",
            "active_phase": policy.active_phase,
            "framework_version": __version__,
            "build_status_input": args.build_status,
            "deployment_status_input": args.deployment_status,
            "test_status_input": args.test_status,
            "test_coverage_input": args.test_coverage_percent,
        }
    )

    results, findings, quality_gate = _collect(args, context, policy, capabilities, stages)

    # --- FINDING AGGREGATION (Phase 4) -----------------------------------
    baseline, baseline_source, baseline_notes = load_baseline(args.baseline or None)
    exceptions, exceptions_source, exception_notes = load_exceptions(args.exceptions or None)
    trustworthy = {r.category_key for r in results if r.is_trustworthy}
    lifecycle = apply_lifecycle(
        findings, baseline, baseline_source, exceptions, exceptions_source, trustworthy
    )
    lifecycle.notes.extend(baseline_notes)
    lifecycle.notes.extend(exception_notes)
    _log(
        "lifecycle: new=%d existing=%d fixed=%d suppressed=%d expired=%d"
        % (lifecycle.new, lifecycle.existing, lifecycle.fixed,
           lifecycle.false_positive + lifecycle.accepted_risk, lifecycle.expired_exceptions)
    )

    # --- CROSS-SCANNER CORRELATION ---------------------------------------
    # Additive: nothing is merged or dropped. Two engines finding the same defect
    # is stronger evidence than one, and it is recorded as such.
    correlation = correlate(findings)
    _log(
        "correlation: %d defect(s) corroborated by more than one scanner, covering %d finding(s)"
        % (len(correlation.corroborated_groups), correlation.findings_correlated)
    )

    # --- EXPLOITABILITY ENRICHMENT ---------------------------------------
    # Deliberately applied AFTER lifecycle and BEFORE reporting, and deliberately
    # not an input to the status engine below. Enrichment orders findings; it must
    # never decide them, because a verdict that depends on a third-party API is a
    # verdict that changes when that API has an outage.
    enrichment = enrich_findings(
        findings,
        enable_epss=not args.no_enrichment,
        enable_kev=not args.no_enrichment,
        timeout=args.enrichment_timeout,
        epss_file=args.epss_file,
        kev_file=args.kev_file,
    )
    _log(
        "enrichment: epss=%s kev=%s cves=%d scored=%d kev_matches=%d"
        % (enrichment.epss_status, enrichment.kev_status, enrichment.cves_seen,
           enrichment.cves_scored, enrichment.kev_matches)
    )
    if enrichment.epss_status == "EPSS_UNAVAILABLE" or enrichment.kev_status == "KEV_UNAVAILABLE":
        _log("  %s" % enrichment.statement())

    assessment = StatusEngine(policy).evaluate(
        context=context,
        capabilities=capabilities,
        scanner_results=results,
        findings=findings,
        quality_gate=quality_gate,
        lifecycle=lifecycle,
        stages=stages,
        import_failures=import_failures(),
    )

    # File-level coverage census. Built AFTER collection so it reflects which
    # scanners actually completed -- a scanner that failed is credited with
    # nothing, and the files it would have read surface as unanalysed rather
    # than being quietly attributed to it.
    file_coverage = build_manifest(
        args.workspace, results, list(capabilities.get("languages") or [])
    )
    if file_coverage.get("available"):
        _log("file coverage: %d/%d code files analysed (%.1f%%)"
             % (file_coverage["code_files_analysed"], file_coverage["code_files"],
                file_coverage["coverage_percent"]))
        if not file_coverage.get("complete"):
            _log("  %s" % file_coverage["statement"])
    else:
        _log("file coverage: NOT ESTABLISHED (%s)" % file_coverage.get("reason", ""))

    # --- DEPLOYMENT READINESS --------------------------------------------
    # Computed AFTER the status engine and AFTER the coverage census, because
    # it consumes both. Deliberately NOT an input to either: readiness must
    # never be able to change a security verdict, only to describe it alongside
    # everything else this run did and did not establish.
    #
    # Nothing here suppresses, downgrades or reclassifies a finding. Findings
    # lower the readiness score and appear as conditions or blockers; they
    # remain in the report at full severity either way.
    reported_coverage = readiness_model.parse_coverage_percent(args.test_coverage_percent)
    if args.test_coverage_percent and reported_coverage is None:
        _log(
            "test coverage %r is not a percentage between 0 and 100; recording it as "
            "NOT_REPORTED rather than guessing a value" % args.test_coverage_percent
        )
    readiness = readiness_model.assess(
        policy=policy,
        assessment=assessment,
        findings=findings,
        scanner_results=results,
        file_coverage=file_coverage,
        test_status=args.test_status,
        test_coverage_percent=reported_coverage,
        import_failures=import_failures(),
    )
    _log(
        "readiness: %.1f%% (assurance %.1f%%) decision=%s evidence=%s blockers=%d conditions=%d unknowns=%d"
        % (readiness.readiness_percent, readiness.assurance_percent, readiness.decision,
           readiness.evidence_status, len(readiness.blockers), len(readiness.conditions),
           len(readiness.unknowns))
    )
    for problem in readiness.integrity_problems:
        _log("  EVIDENCE INTEGRITY: %s" % problem)

    report = build_report(
        context, capabilities, policy, assessment, findings, results,
        file_coverage=file_coverage,
        enrichment=enrichment.to_dict(),
        correlation=correlation.to_dict(),
        readiness=readiness.to_dict(),
    )

    table_rows = args.max_table_rows or None
    detailed = args.max_detailed_findings or None

    # Every artefact this run manages to write is recorded, and every one it
    # fails to write is recorded too. That record IS the pipeline status: the
    # difference between "the framework finished" and "the framework finished
    # its most important half" has to be visible without reading a log.
    artefacts_written: List[str] = []
    artefact_errors: List[str] = []

    def render_all() -> Optional[int]:
        """Write every report format from the one report dict.

        Called a second time only if the evidence manifest fails, so that a
        COMPLETED_WITH_ERRORS pipeline status reaches the Markdown and the PDF
        as well as the JSON. Five formats saying different things about the same
        run is the failure mode the single-source-of-truth design exists to
        prevent, and a rare error path is no reason to allow it.
        """
        del artefacts_written[:]
        _log("wrote %s" % write_json(report, args.output))
        artefacts_written.append("final-report.json")
        _log("wrote %s" % write_normalized_findings(findings, args.output))
        artefacts_written.append("normalized-findings.json")
        # findings.csv is the untruncated list. The narrative reports are bounded
        # so they stay readable; this one exists so nothing is only summarised.
        _log("wrote %s" % write_csv(report, args.output))
        artefacts_written.append("findings.csv")
        # SARIF puts each finding on its line in the pull request and in the
        # repository's Security tab. A finding nobody sees is one nobody fixes.
        _log("wrote %s" % write_sarif(report, args.output))
        artefacts_written.append("security.sarif")
        _log("wrote %s"
             % write_markdown(report, args.output, max_table_rows=table_rows, max_detailed=detailed))
        artefacts_written.append("report.md")
        try:
            _log("wrote %s"
                 % write_pdf(report, args.output, max_table_rows=table_rows, max_detailed=detailed))
            artefacts_written.append("security-report.pdf")
        except PdfGenerationError as exc:
            _log("ERROR: %s" % exc)
            return EXIT_FRAMEWORK_ERROR
        return None

    def pipeline_block() -> Dict[str, Any]:
        status_value = (
            readiness_model.PIPELINE_COMPLETED_WITH_ERRORS if artefact_errors
            else readiness_model.PIPELINE_COMPLETED
        )
        return {
            "status": status_value,
            "artifacts_written": list(artefacts_written),
            "errors": list(artefact_errors),
            "statement": (
                "The framework completed every stage and produced every artefact."
                if status_value == readiness_model.PIPELINE_COMPLETED else
                "The framework completed, but %d artefact(s) could not be produced. The reports "
                "that WERE produced are valid; the missing ones are named above."
                % len(artefact_errors)
            ),
            "note": (
                "PIPELINE describes this framework's own execution. It is not a security result "
                "and it is not a deployment decision. A run that discovers a hundred "
                "vulnerabilities and reports every one of them is a COMPLETED pipeline."
            ),
        }

    def publish() -> Optional[int]:
        """Render every format, then record what was actually written.

        The artefact list is only knowable after the writes, and the JSON is one
        of the things written -- so it is serialised once to produce the files
        and once more to record them. The second write is cheap and is what
        makes `pipeline.artifacts_written` describe reality rather than
        intention. `evidence-manifest.json` is deliberately absent from the
        list: it is written after this, and it inventories every artefact with a
        digest anyway, so listing it here would only invalidate its own hash of
        this file.
        """
        report["pipeline"] = pipeline_block()
        outcome = render_all()
        if outcome is not None:
            return outcome
        report["pipeline"]["artifacts_written"] = list(artefacts_written)
        write_json(report, args.output)
        return None

    failure = publish()
    if failure is not None:
        return failure

    # --- AUDIT EVIDENCE ---------------------------------------------------
    # Written LAST, so it can hash every artefact this run actually produced.
    # A report is an assertion; a report plus this manifest is a record.
    manifest = build_evidence_manifest(
        report, results, args.output, policy_paths=policy.source_paths,
    )
    if not manifest.get("available"):
        artefact_errors.append(
            "the evidence manifest could not be assembled: %s"
            % manifest.get("reason", "reason not recorded")
        )
        _log("WARNING: %s" % manifest.get("reason", "evidence manifest unavailable"))
        # The manifest is built last because it hashes everything before it, so
        # its failure is only knowable after the reports are already on disk.
        # Re-render them with the corrected status and rebuild the manifest over
        # what is now actually there -- otherwise the digests describe files
        # that no longer exist in that form.
        failure = publish()
        if failure is not None:
            return failure
        manifest = build_evidence_manifest(
            report, results, args.output, policy_paths=policy.source_paths,
        )
    _log("wrote %s" % write_manifest(manifest, args.output))
    pipeline_status = report["pipeline"]["status"]

    _write_step_summary(report)
    _write_outputs(report)

    status = report["status"]
    _log("=" * 70)
    _log("PIPELINE            : %s" % pipeline_status)
    _log("BUILD               : %s" % status["build"])
    _log("DEPLOYMENT          : %s" % status["deployment"])
    _log("SECURITY            : %s" % status["security"])
    _log("RUNTIME_SECURITY    : %s" % status["runtime_security"])
    _log("EVIDENCE            : %s" % readiness.evidence_status)
    _log("READINESS           : %.1f%% (assurance %.1f%%)"
         % (readiness.readiness_percent, readiness.assurance_percent))
    _log("DEPLOYMENT DECISION : %s" % readiness.decision)
    _log("deployment permitted: %s" % readiness.deployment_permitted)
    _log("scope               : %s" % status["verdict_scope"])
    _log("coverage complete   : %s" % status["coverage_complete"])
    _log("=" * 70)
    _log(readiness.statement)
    for reason in readiness.decision_rationale:
        _log("  %s" % reason)
    _log("=" * 70)

    return _resolve_exit_code(args, status, readiness)


def _resolve_exit_code(
    args: argparse.Namespace, status: Dict[str, Any], readiness: Any
) -> int:
    """Mirror ONE computed verdict into the exit status, at the caller's request.

    Every verdict is already published in the report and in the step outputs, so
    the exit code adds no information -- it only decides whether the CI job goes
    red. Which is exactly why it defaults to `never`: a red job stops the stages
    after it, and the stages after a security scan are the ones that publish
    what the scan found.

    Note what is NOT here: no branch inspects a finding, a severity or a count.
    A finding can only reach this function through a verdict that was computed
    from it and explained in the report.
    """
    # Backwards compatibility. The old flag is the old behaviour, exactly.
    mode = FAIL_ON_SECURITY if getattr(args, "fail_on_security", False) else args.fail_on

    if mode == FAIL_ON_NEVER:
        return EXIT_OK

    if mode == FAIL_ON_EVIDENCE:
        if readiness.evidence_status == readiness_model.EVIDENCE_UNTRUSTWORTHY:
            _log("--fail-on evidence: the evidence set contradicts itself; exiting %d."
                 % EXIT_EVIDENCE_UNTRUSTWORTHY)
            return EXIT_EVIDENCE_UNTRUSTWORTHY
        return EXIT_OK

    if mode == FAIL_ON_DECISION:
        # UNTRUSTWORTHY evidence is reported on its own code even here: "we
        # cannot trust the evidence" and "the evidence says do not deploy" are
        # different problems for whoever reads the exit status.
        if readiness.evidence_status == readiness_model.EVIDENCE_UNTRUSTWORTHY:
            _log("--fail-on decision: evidence is untrustworthy; exiting %d."
                 % EXIT_EVIDENCE_UNTRUSTWORTHY)
            return EXIT_EVIDENCE_UNTRUSTWORTHY
        if readiness.decision != readiness_model.DECISION_READY:
            _log("--fail-on decision: DEPLOYMENT DECISION = %s; exiting %d."
                 % (readiness.decision, EXIT_NOT_DEPLOYABLE))
            return EXIT_NOT_DEPLOYABLE
        return EXIT_OK

    # FAIL_ON_SECURITY -- the legacy behaviour, unchanged.
    if status["security"] == SECURITY_FAILED:
        return EXIT_SECURITY_FAILED
    if status["security"] != SECURITY_PASS:
        return EXIT_SECURITY_NOT_VERIFIED
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "detect":
            return command_detect(args)
        if args.command == "tools":
            return command_tools(args)
        if args.command == "run":
            return command_run(args)
    except Exception:  # noqa: BLE001 - top-level guard
        traceback.print_exc()
        _log("FRAMEWORK ERROR: the run did not complete. No security verdict is implied by this failure.")
        return EXIT_FRAMEWORK_ERROR
    parser.error("unknown command")
    return EXIT_FRAMEWORK_ERROR


if __name__ == "__main__":
    sys.exit(main())
