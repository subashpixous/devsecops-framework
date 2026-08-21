"""report.md -- human-readable rendering of final-report.json.

Presentation rule enforced here: the deployment result and the security result
are rendered as two separate, visually distinct blocks. Nothing in this file may
combine them into a single "overall" verdict.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

MAX_DETAILED_FINDINGS = 60
MAX_TABLE_ROWS = 400

STATUS_MARK = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "FAILED": "FAILED",
    "NOT_VERIFIED": "NOT VERIFIED",
    "NOT_TESTED": "NOT TESTED",
    "NOT_IMPLEMENTED": "NOT IMPLEMENTED",
    "NOT_APPLICABLE": "NOT APPLICABLE",
    "DEPLOYED": "DEPLOYED",
    "SKIPPED": "SKIPPED",
    "UNKNOWN": "UNKNOWN (NOT_ESTABLISHED)",
}


def _mark(status: str) -> str:
    return STATUS_MARK.get(str(status).upper(), str(status))


def _escape(text: Any) -> str:
    value = str(text if text is not None else "")
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _truncate(text: Any, limit: int = 160) -> str:
    value = _escape(text)
    return value if len(value) <= limit else value[: limit - 1] + "\u2026"


def render_markdown(report: Dict[str, Any]) -> str:  # noqa: C901 - linear document assembly
    project = report["project"]
    status = report["status"]
    verdict = report["verdict"]
    findings = report["findings"]
    lines: List[str] = []
    add = lines.append

    add("# Application Security Report")
    add("")
    add("_%s v%s -- Phase %s_"
        % (report["framework"]["name"], report["framework"]["version"], report["framework"]["active_phase"]))
    add("")
    add("Generated: `%s`" % report["generated_at"])
    add("")

    # --- Two separate results -------------------------------------------------
    add("---")
    add("")
    add("## 1. APPLICATION DEPLOYMENT RESULT")
    add("")
    add("| Aspect | Status |")
    add("|---|---|")
    add("| Build | **%s** |" % _mark(status["build"]))
    add("| Deployment | **%s** |" % _mark(status["deployment"]))
    add("")
    add("---")
    add("")
    add("## 2. APPLICATION SECURITY RESULT")
    add("")
    add("| Aspect | Status |")
    add("|---|---|")
    add("| Security | **%s** |" % _mark(status["security"]))
    add("| Runtime security | **%s** |" % _mark(status["runtime_security"]))
    add("| Verdict scope | `%s` |" % status["verdict_scope"])
    add("| Security coverage complete | **%s** |" % ("YES" if status["coverage_complete"] else "NO"))
    add("")
    add("> %s" % status["independence_note"])
    add("")
    if not status["coverage_complete"]:
        add("> **This is not a full security assessment.** Categories marked NOT_IMPLEMENTED or "
            "NOT_VERIFIED below were not tested. Their absence from the findings list is not "
            "evidence that no such issue exists.")
        add("")

    # --- Project --------------------------------------------------------------
    add("---")
    add("")
    add("## 3. Project")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add("| Project name | %s |" % _escape(project["project_name"]))
    add("| Repository | %s |" % _escape(project["repository"]))
    add("| Commit | `%s` |" % _escape(project["commit"]))
    add("| Branch | %s |" % _escape(project["branch"]))
    add("| Environment | %s |" % _escape(project["environment"]))
    add("| Deployment target | %s |" % _escape(project["deployment_target"]))
    add("| Deployed URL | %s |" % _escape(project["deployed_url"]))
    add("| Run | %s |" % _escape(project["run_url"]))
    add("")

    capabilities = report.get("capabilities") or {}
    add("**Detected capabilities**")
    add("")
    add("| Capability | Value |")
    add("|---|---|")
    for key in ("languages", "frameworks", "package_manager"):
        add("| %s | %s |" % (key, _escape(", ".join(capabilities.get(key) or []) or "none detected")))
    for key in ("docker", "iac", "kubernetes", "openapi", "frontend", "backend"):
        add("| %s | %s |" % (key, capabilities.get(key)))
    add("| cloud | %s |" % _escape(capabilities.get("cloud") or "NOT_ESTABLISHED"))
    add("")

    # --- Verdict --------------------------------------------------------------
    add("---")
    add("")
    add("## 4. Security Verdict")
    add("")
    add("**SECURITY = %s**" % _mark(verdict["security_status"]))
    add("")
    for reason in verdict["rationale"]:
        add("- %s" % reason)
    add("")
    if verdict["threshold_breaches"]:
        add("**Policy threshold breaches**")
        add("")
        add("| Severity | Open findings | Permitted |")
        add("|---|---|---|")
        for breach in verdict["threshold_breaches"]:
            add("| %s | %d | %d |" % (breach["severity"], breach["count"], breach["threshold"]))
        add("")

    # --- Upstream quality gate ------------------------------------------------
    gate = report.get("quality_gate") or {}
    add("---")
    add("")
    add("## 5. SonarQube Quality Gate")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add("| Gate status | **%s** |" % _escape(gate.get("status", "UNKNOWN")))
    add("| Conditions evaluated | %d |" % len(gate.get("conditions") or []))
    add("| Failing conditions | %d |" % len(gate.get("failing_conditions") or []))
    add("")
    if gate.get("conditions"):
        add("| Metric | Comparator | Threshold | Actual | Status |")
        add("|---|---|---|---|---|")
        for condition in gate["conditions"]:
            add("| %s | %s | %s | %s | %s |" % (
                _escape(condition.get("metric")), _escape(condition.get("comparator")),
                _escape(condition.get("threshold")), _escape(condition.get("actual")),
                _escape(condition.get("status")),
            ))
        add("")
    if gate.get("status") == "UNKNOWN":
        add("> The quality gate status could not be retrieved. It is recorded as UNKNOWN, never as passing.")
        add("")

    # --- Counts ---------------------------------------------------------------
    add("---")
    add("")
    add("## 6. Findings Summary")
    add("")
    add("| Metric | Count |")
    add("|---|---|")
    add("| Total findings collected | %d |" % findings["total"])
    add("| Open findings | %d |" % findings["open"])
    add("")
    add("**Severity breakdown (all open findings)**")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity, count in findings["severity_breakdown"].items():
        add("| %s | %d |" % (severity, count))
    add("")
    add("**Severity breakdown (security-relevant open findings only)**")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for severity, count in findings["security_severity_breakdown"].items():
        add("| %s | %d |" % (severity, count))
    add("")

    # --- Findings -------------------------------------------------------------
    add("---")
    add("")
    add("## 7. Findings")
    add("")
    items = findings["items"]
    if not items:
        add("No findings were returned by the scanners that executed in this run.")
        add("")
        add("> This is not a statement that the application is secure. See sections 9-11 for the "
            "controls that were not executed.")
        add("")
    else:
        shown = items[:MAX_TABLE_ROWS]
        add("| # | Severity | Category | File | Line | Rule | Description |")
        add("|---|---|---|---|---|---|---|")
        for index, finding in enumerate(shown, 1):
            add("| %d | %s | %s | %s | %s | %s | %s |" % (
                index, finding["severity"], finding["category"],
                _truncate(finding["file"], 60) or "-", finding["line"] or "-",
                _escape(finding.get("rule")) or "-", _truncate(finding["description"], 90),
            ))
        add("")
        if len(items) > MAX_TABLE_ROWS:
            add("> Table truncated to %d of %d findings. The complete set is in `final-report.json` "
                "and `normalized-findings.json`." % (MAX_TABLE_ROWS, len(items)))
            add("")

        add("### Finding detail")
        add("")
        for index, finding in enumerate(items[:MAX_DETAILED_FINDINGS], 1):
            add("#### %d. [%s] %s" % (index, finding["severity"], _truncate(finding["description"], 110)))
            add("")
            add("| Field | Value |")
            add("|---|---|")
            add("| Fingerprint | `%s` |" % finding["fingerprint"])
            add("| Tool | %s |" % _escape(finding["tool"]))
            add("| Category | %s |" % _escape(finding["category"]))
            add("| Severity | %s |" % _escape(finding["severity"]))
            add("| CWE | %s |" % (_escape(finding["cwe"]) or "not mapped"))
            add("| OWASP | %s |" % (_escape(finding["owasp"]) or "not mapped"))
            add("| File | `%s` |" % (_escape(finding["file"]) or "n/a"))
            add("| Line | %s |" % (finding["line"] or "n/a"))
            add("| Endpoint | %s |" % (_escape(finding["endpoint"]) or "n/a"))
            add("| Status | %s |" % _escape(finding["status"]))
            add("| Evidence | %s |" % _truncate(finding["evidence"], 220))
            add("| Impact | %s |" % _truncate(finding["impact"], 300))
            add("| Remediation | %s |" % _truncate(finding["remediation"], 300))
            add("| First seen | %s |" % _escape(finding["first_seen"]))
            add("| Last seen | %s |" % _escape(finding["last_seen"]))
            add("| Commit | `%s` |" % _escape(finding["commit"]))
            add("| Branch | %s |" % _escape(finding["branch"]))
            add("")
        if len(items) > MAX_DETAILED_FINDINGS:
            add("> Detailed entries truncated to the %d most severe of %d findings."
                % (MAX_DETAILED_FINDINGS, len(items)))
            add("")

    # --- Scanners -------------------------------------------------------------
    add("---")
    add("")
    add("## 8. Scanner Execution")
    add("")
    add("| Tool | Category | Status | Errors | Warnings |")
    add("|---|---|---|---|---|")
    for scanner in report["scanners"]:
        add("| %s | %s | **%s** | %d | %d |" % (
            _escape(scanner["tool"]), _escape(scanner["category_key"]), _escape(scanner["status"]),
            len(scanner["errors"]), len(scanner["warnings"]),
        ))
    add("")
    failures = [s for s in report["scanners"] if s["errors"]]
    if failures:
        add("### Scanner failures")
        add("")
        for scanner in failures:
            for error in scanner["errors"]:
                add("- **%s**: %s" % (_escape(scanner["tool"]), _escape(error)))
        add("")
    warnings = [s for s in report["scanners"] if s["warnings"]]
    if warnings:
        add("### Scanner warnings")
        add("")
        for scanner in warnings:
            for warning in scanner["warnings"]:
                add("- **%s**: %s" % (_escape(scanner["tool"]), _escape(warning)))
        add("")

    # --- Category matrix ------------------------------------------------------
    add("---")
    add("")
    add("## 9. Security Category Matrix")
    add("")
    add("Every category resolves to exactly one status. Nothing is skipped silently.")
    add("")
    add("| Category | Phase | Status | Findings | Reason |")
    add("|---|---|---|---|---|")
    for category in report["categories"]:
        add("| %s | %d | **%s** | %d | %s |" % (
            _escape(category["title"]), category["phase"], _mark(category["status"]),
            category["finding_count"], _truncate(category["reason"], 130),
        ))
    add("")

    summary = report["category_summary"]
    for label, key in (
        ("10. Categories NOT TESTED in this run (NOT_VERIFIED)", "not_verified"),
        ("11. Categories NOT IMPLEMENTED yet", "not_implemented"),
    ):
        add("---")
        add("")
        add("## %s" % label)
        add("")
        entries = summary.get(key) or []
        if not entries:
            add("None.")
            add("")
            continue
        for entry in entries:
            add("- **%s** (phase %d) -- %s" % (_escape(entry["title"]), entry["phase"], _escape(entry["reason"])))
            for note in entry.get("notes") or []:
                add("  - %s" % _escape(note))
        add("")

    not_applicable = summary.get("not_applicable") or []
    add("---")
    add("")
    add("## 12. Categories NOT APPLICABLE to this project")
    add("")
    if not_applicable:
        for entry in not_applicable:
            add("- **%s** -- %s" % (_escape(entry["title"]), _escape(entry["reason"])))
    else:
        add("None.")
    add("")

    # --- Limitations ----------------------------------------------------------
    add("---")
    add("")
    add("## 13. Automation Limitations")
    add("")
    for limitation in report["limitations"]:
        add("- **%s**: %s" % (_escape(limitation["code"]), _escape(limitation["detail"])))
    add("")

    add("### Manual security controls -- NOT tested by any scanner")
    add("")
    add("| Control | Status | Why automation cannot cover it |")
    add("|---|---|---|")
    for control in report["manual_controls"]:
        add("| %s | **%s** | %s |" % (
            _escape(control["title"]), _escape(control["status"]),
            _truncate(control["why_not_automatable"], 150),
        ))
    add("")

    # --- Final verdict --------------------------------------------------------
    add("---")
    add("")
    add("## 14. Final Security Verdict")
    add("")
    add("| | |")
    add("|---|---|")
    add("| **BUILD** | %s |" % _mark(status["build"]))
    add("| **DEPLOYMENT** | %s |" % _mark(status["deployment"]))
    add("| **SECURITY** | %s |" % _mark(status["security"]))
    add("| **RUNTIME_SECURITY** | %s |" % _mark(status["runtime_security"]))
    add("")
    add("Scope of this verdict: `%s`" % status["verdict_scope"])
    add("")
    add("_A deployment result never implies a security result. This report asserts security only "
        "for the controls listed as PASS or FAILED above._")
    add("")
    return "\n".join(lines)


def write_markdown(report: Dict[str, Any], output_dir: str, filename: str = "report.md") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
    return path
