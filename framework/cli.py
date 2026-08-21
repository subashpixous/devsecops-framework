"""Command line entrypoint.

    python -m framework.cli detect  --workspace . --output security-results
    python -m framework.cli run     --workspace . --output security-results

`run` executes the whole pipeline:

    detect -> collect -> normalize -> evaluate -> report

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
from typing import Any, Dict, List, Optional

from . import __version__
from .collectors.base import ScannerResult
from .core.categories import SECURITY_FAILED, SECURITY_NOT_VERIFIED, SECURITY_PASS
from .core.context import RunContext
from .core.policy import Policy
from .core.registry import load_builtin_scanners, scanners_for_phase
from .core.schema import Finding
from .core.status_engine import StatusEngine
from .detect.detector import detect
from .report.json_writer import build_report, write_json, write_normalized_findings
from .report.markdown_writer import write_markdown
from .report.pdf_writer import PdfGenerationError, write_pdf

EXIT_OK = 0
EXIT_SECURITY_FAILED = 2
EXIT_SECURITY_NOT_VERIFIED = 3
EXIT_FRAMEWORK_ERROR = 4


def _log(message: str) -> None:
    print("[devsecops-framework] %s" % message, flush=True)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", default=os.environ.get("GITHUB_WORKSPACE", "."), help="Repository root to inspect.")
    parser.add_argument("--output", default="security-results", help="Directory for generated artifacts.")
    parser.add_argument("--project-name", default="", help="Override the detected project name.")
    parser.add_argument("--environment", default="", help="Environment label (e.g. production, qa).")
    parser.add_argument("--deployment-target", default="", help="Deployment target. Left NOT_ESTABLISHED if omitted.")
    parser.add_argument("--deployed-url", default="", help="Live URL. Left NOT_ESTABLISHED if omitted.")


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devsecops-framework", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    detect_parser = subparsers.add_parser("detect", help="Emit capabilities.json only.")
    _add_common_arguments(detect_parser)

    run_parser = subparsers.add_parser("run", help="Run the full pipeline.")
    _add_common_arguments(run_parser)
    run_parser.add_argument("--policy", default="", help="Path to a policy override file.")
    run_parser.add_argument("--active-phase", type=int, default=0, help="Override the policy's active phase.")
    run_parser.add_argument("--sonar-project-key", default="", help="Override SonarQube project key resolution.")
    run_parser.add_argument("--build-status", default="", help="Build result reported by the caller.")
    run_parser.add_argument("--deployment-status", default="", help="Deployment result reported by the caller.")
    run_parser.add_argument(
        "--fail-on-security",
        action="store_true",
        help="Exit non-zero when SECURITY is not PASS. Off by default so the framework observes without blocking.",
    )
    run_parser.add_argument(
        "--sonar-payload",
        default="",
        help="Load a previously captured raw payload instead of calling the API (self-test only). "
             "Recorded in the report as a non-live source.",
    )
    return parser


def _capability_overrides(args: argparse.Namespace) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    if args.deployment_target:
        overrides["deployment_target"] = args.deployment_target
    if args.deployed_url:
        overrides["deployed_url"] = args.deployed_url
    return overrides


def command_detect(args: argparse.Namespace) -> int:
    capabilities = detect(args.workspace, _capability_overrides(args))
    os.makedirs(args.output, exist_ok=True)
    path = os.path.join(args.output, "capabilities.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(capabilities, handle, indent=2, sort_keys=False)
        handle.write("\n")
    _log("capabilities written to %s" % path)
    print(json.dumps(capabilities, indent=2))
    return EXIT_OK


def _load_payload_override(path: str, results: List[ScannerResult]) -> Optional[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _collect(args: argparse.Namespace, context: RunContext, policy: Policy) -> tuple:
    """Run every scanner registered for the active phase."""
    load_builtin_scanners()
    registrations = scanners_for_phase(policy.active_phase)

    results: List[ScannerResult] = []
    findings: List[Finding] = []
    quality_gate: Dict[str, Any] = {}

    if not registrations:
        _log("no scanners registered for phase %d" % policy.active_phase)

    for registration in registrations:
        _log("collecting: %s (%s)" % (registration.tool, registration.category_key))
        collector = registration.collector_factory(
            workspace=args.workspace,
            branch=context.branch,
            project_key=args.sonar_project_key or None,
        )
        try:
            result = collector.collect()
        except Exception as exc:  # noqa: BLE001 - a collector must never take down the run
            result = ScannerResult(tool=registration.tool, category_key=registration.category_key)
            result.fail("collector raised an unexpected exception: %s" % exc).finish()
            _log("collector %s raised: %s" % (registration.tool, exc))

        if args.sonar_payload and registration.tool == "sonarqube":
            try:
                result.payload = _load_payload_override(args.sonar_payload, results)
                result.metadata["payload_source"] = "local file (%s) -- NOT a live scan" % os.path.basename(args.sonar_payload)
                result.errors.clear()
                result.succeed()
                result.warnings.append(
                    "Results were loaded from a local payload file rather than a live SonarQube server. "
                    "This run does not prove connectivity to the analysis server."
                )
            except (OSError, ValueError) as exc:
                result.fail("could not load payload override %s: %s" % (args.sonar_payload, exc))
        else:
            result.metadata.setdefault("payload_source", "live SonarQube Web API (read-only)")

        result.write_raw(args.output, "%s.json" % registration.tool)
        results.append(result)

        adapter = registration.adapter_factory()
        try:
            scanner_findings = adapter.normalize(result, context)
        except Exception as exc:  # noqa: BLE001
            result.fail("adapter raised an unexpected exception: %s" % exc)
            scanner_findings = []
            _log("adapter %s raised: %s" % (registration.tool, exc))
        findings.extend(scanner_findings)

        gate = adapter.summarize_gate(result)
        if gate and gate.get("status") != "UNKNOWN":
            quality_gate = gate
        elif gate and not quality_gate:
            quality_gate = gate

        _log(
            "  -> status=%s findings=%d errors=%d warnings=%d"
            % (result.status, len(scanner_findings), len(result.errors), len(result.warnings))
        )

    return results, findings, quality_gate


def _write_step_summary(report: Dict[str, Any]) -> None:
    """Publish the headline result to the GitHub Actions job summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    status = report["status"]
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
        "Open findings: **%d** (severity: %s)"
        % (
            report["findings"]["open"],
            ", ".join("%s=%d" % (k, v) for k, v in report["findings"]["severity_breakdown"].items() if v),
        ),
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
    """Expose the statuses as GitHub Actions step outputs."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    status = report["status"]
    try:
        with open(output_path, "a", encoding="utf-8") as handle:
            handle.write("build_status=%s\n" % status["build"])
            handle.write("deployment_status=%s\n" % status["deployment"])
            handle.write("security_status=%s\n" % status["security"])
            handle.write("runtime_security_status=%s\n" % status["runtime_security"])
            handle.write("open_findings=%d\n" % report["findings"]["open"])
            handle.write("coverage_complete=%s\n" % str(status["coverage_complete"]).lower())
    except OSError as exc:
        _log("could not write step outputs: %s" % exc)


def command_run(args: argparse.Namespace) -> int:  # noqa: C901 - linear orchestration
    os.makedirs(args.output, exist_ok=True)

    policy = Policy.load(args.policy or None)
    if args.active_phase:
        policy.active_phase = args.active_phase
    _log("policy=%s active_phase=%d required=%s" % (policy.name, policy.active_phase, policy.required_categories))

    capabilities = detect(args.workspace, _capability_overrides(args))
    capabilities_path = os.path.join(args.output, "capabilities.json")
    with open(capabilities_path, "w", encoding="utf-8") as handle:
        json.dump(capabilities, handle, indent=2, sort_keys=False)
        handle.write("\n")
    _log("detected languages=%s docker=%s iac=%s k8s=%s openapi=%s" % (
        capabilities["languages"], capabilities["docker"], capabilities["iac"],
        capabilities["kubernetes"], capabilities["openapi"],
    ))

    context = RunContext.from_environment(
        {
            "project_name": args.project_name,
            "environment": args.environment,
            # Detection output is only a fallback; an explicit caller value wins.
            "deployment_target": args.deployment_target or capabilities.get("deployment_target") or "",
            "deployed_url": args.deployed_url or capabilities.get("deployed_url") or "",
            "active_phase": policy.active_phase,
            "framework_version": __version__,
            "build_status_input": args.build_status,
            "deployment_status_input": args.deployment_status,
        }
    )

    results, findings, quality_gate = _collect(args, context, policy)

    assessment = StatusEngine(policy).evaluate(
        context=context,
        capabilities=capabilities,
        scanner_results=results,
        findings=findings,
        quality_gate=quality_gate,
    )

    report = build_report(context, capabilities, policy, assessment, findings, results)

    json_path = write_json(report, args.output)
    findings_path = write_normalized_findings(findings, args.output)
    markdown_path = write_markdown(report, args.output)
    _log("wrote %s" % json_path)
    _log("wrote %s" % findings_path)
    _log("wrote %s" % markdown_path)

    try:
        pdf_path = write_pdf(report, args.output)
        _log("wrote %s" % pdf_path)
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
        if status["security"] == SECURITY_NOT_VERIFIED:
            return EXIT_SECURITY_NOT_VERIFIED
        if status["security"] != SECURITY_PASS:
            return EXIT_SECURITY_NOT_VERIFIED
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "detect":
            return command_detect(args)
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
