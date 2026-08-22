"""Command line entrypoint.

    python -m framework.cli detect --workspace .
    python -m framework.cli tools
    python -m framework.cli run --workspace . --output security-results

`run` executes the approved pipeline:

    detect -> collect (per stage) -> normalize -> aggregate (lifecycle)
           -> evaluate -> report

Exit codes:
    0  reports generated (verdict may be any value unless --fail-on-security)
    2  SECURITY = FAILED        and --fail-on-security was requested
    3  SECURITY = NOT_VERIFIED  and --fail-on-security was requested
    4  the framework itself failed to produce a complete report

Exit code 4 exists so a broken framework is loud. It never converts into a
passing security verdict.
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
from .report.json_writer import build_report, write_json, write_normalized_findings
from .report.markdown_writer import write_markdown
from .report.pdf_writer import PdfGenerationError, write_pdf

EXIT_OK = 0
EXIT_SECURITY_FAILED = 2
EXIT_SECURITY_NOT_VERIFIED = 3
EXIT_FRAMEWORK_ERROR = 4

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
    run_parser.add_argument("--build-status", default="")
    run_parser.add_argument("--deployment-status", default="")
    run_parser.add_argument("--images", default="", help="Comma-separated image refs for image/SBOM/signature scans.")
    run_parser.add_argument("--cloud", default="", help="Cloud provider for posture scanning (aws|azure|gcp).")
    run_parser.add_argument("--aws-region", default="")
    run_parser.add_argument("--zap-mode", default="baseline", choices=("baseline", "full"))
    run_parser.add_argument("--bundle-dirs", default="", help="Comma-separated built frontend directories.")
    run_parser.add_argument("--openapi-files", default="", help="Comma-separated OpenAPI spec paths.")
    run_parser.add_argument("--baseline", default="", help="Previous normalized-findings.json for lifecycle diffing.")
    run_parser.add_argument("--exceptions", default="", help="Exceptions/accepted-risk file (YAML or JSON).")
    run_parser.add_argument("--fail-on-security", action="store_true")
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
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    status = report["status"]
    lifecycle = (report.get("lifecycle") or {}).get("counts") or {}
    lines = [
        "## Security validation result",
        "",
        "| Result | Status |",
        "|---|---|",
        "| Build | `%s` |" % status["build"],
        "| Deployment | `%s` |" % status["deployment"],
        "| **Security** | **`%s`** |" % status["security"],
        "| **Runtime security** | **`%s`** |" % status["runtime_security"],
        "",
        "Scope: `%s`" % status["verdict_scope"],
        "",
        "Findings: **%d open** (new %s / existing %s / fixed %s)"
        % (report["findings"]["open"], lifecycle.get("new", "?"),
           lifecycle.get("existing", "?"), lifecycle.get("fixed", "?")),
        "",
        "> A deployment result never implies a security result.",
        "",
    ]
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

    report = build_report(context, capabilities, policy, assessment, findings, results)

    _log("wrote %s" % write_json(report, args.output))
    _log("wrote %s" % write_normalized_findings(findings, args.output))
    _log("wrote %s" % write_markdown(report, args.output))
    try:
        _log("wrote %s" % write_pdf(report, args.output))
    except PdfGenerationError as exc:
        _log("ERROR: %s" % exc)
        return EXIT_FRAMEWORK_ERROR

    _write_step_summary(report)
    _write_outputs(report)

    status = report["status"]
    _log("=" * 70)
    _log("BUILD            : %s" % status["build"])
    _log("DEPLOYMENT       : %s" % status["deployment"])
    _log("SECURITY         : %s" % status["security"])
    _log("RUNTIME_SECURITY : %s" % status["runtime_security"])
    _log("scope            : %s" % status["verdict_scope"])
    _log("coverage complete: %s" % status["coverage_complete"])
    _log("=" * 70)

    if args.fail_on_security:
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
