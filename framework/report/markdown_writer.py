"""report.md -- human-readable rendering of final-report.json.

Presentation rule enforced here: the deployment result and the security result
are rendered as two separate, visually distinct blocks. Nothing in this file may
combine them into a single "overall" verdict.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

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


def render_markdown(
    report: Dict[str, Any],
    max_table_rows: Optional[int] = None,
    max_detailed: Optional[int] = None,
) -> str:  # noqa: C901 - linear document assembly
    project = report["project"]
    status = report["status"]
    verdict = report["verdict"]
    findings = report["findings"]
    # Limits are arguments, not constants: on a legacy codebase the defaults show
    # a fraction of the findings, and a reader with no way to raise them cannot
    # tell a short report from a short list of problems.
    table_limit = MAX_TABLE_ROWS if max_table_rows is None else max(0, int(max_table_rows))
    detail_limit = MAX_DETAILED_FINDINGS if max_detailed is None else max(0, int(max_detailed))

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
    add("## 5. SonarQube Analysis")
    add("")

    # Analysis identity FIRST. The gate verdict is only meaningful once the
    # reader knows which code it describes, so the provenance of the result is
    # stated before the result itself.
    state = gate.get("analysis_state", "SONARQUBE_RESULT_UNAVAILABLE")
    add("| Field | Value |")
    add("|---|---|")
    add("| Analysis state | **`%s`** |" % _escape(state))
    add("| Project key | `%s` |" % _escape(gate.get("project_key", "NOT_ESTABLISHED")))
    add("| Analysis date | `%s` |" % _escape(gate.get("analysis_date", "NOT_ESTABLISHED")))
    add("| Analysis revision | `%s` |" % _escape(gate.get("analysis_revision", "NOT_ESTABLISHED")))
    add("| Commit under validation | `%s` |" % _escape(gate.get("scanned_commit", "NOT_ESTABLISHED")))
    add("| Freshness established by | `%s` |" % _escape(gate.get("freshness_basis", "unknown")))
    add("| Scope | %s |" % _escape(gate.get("branch_scope", "NOT_ESTABLISHED")))
    add("| Gate status | **%s** |" % _escape(gate.get("status", "UNKNOWN")))
    add("| Conditions evaluated | %d |" % len(gate.get("conditions") or []))
    add("| Failing conditions | %d |" % len(gate.get("failing_conditions") or []))
    add("")

    if state == "SONARQUBE_RESULT_STALE":
        add("> **`SONARQUBE_RESULT_STALE` — these results do not describe the code in this run.**")
        add(">")
        add("> %s" % _escape(gate.get("analysis_state_reason", "")))
        add(">")
        add("> The findings below are reported for information. They are NOT evidence about "
            "this commit, and this category cannot reach PASS on them.")
        add("")
    elif state == "SONARQUBE_PERMISSION_ERROR":
        add("> **`SONARQUBE_PERMISSION_ERROR` — the analysis server rejected our credentials.**")
        add(">")
        add("> The token is invalid, expired, or lacks 'Browse' permission on this project. "
            "No assertion about static analysis can be made from this run.")
        add("")
    elif state == "SONARQUBE_RESULT_UNAVAILABLE":
        add("> **`SONARQUBE_RESULT_UNAVAILABLE` — no usable analysis was retrieved.** "
            "This is NOT a pass.")
        add("")
    elif gate.get("freshness_basis") == "age":
        add("> Freshness was established by analysis **age**, not by revision. The server "
            "reported no revision for its last analysis, so it cannot be proven that the "
            "analysis covered this exact commit.")
        add("")

    measures = gate.get("measures") or {}
    if measures:
        add("**Project measures**")
        add("")
        add("| Metric | Value |")
        add("|---|---|")
        for metric in ("ncloc", "files", "coverage", "line_coverage", "branch_coverage",
                       "duplicated_lines_density", "vulnerabilities", "bugs",
                       "code_smells", "security_hotspots"):
            if metric in measures:
                add("| %s | %s |" % (_escape(metric), _escape(measures[metric])))
        add("")
        add("> Metrics the server does not hold are omitted rather than shown as zero: a "
            "project with no coverage measurement is not a project with 0% coverage.")
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

    # --- Lifecycle ------------------------------------------------------------
    lifecycle = report.get("lifecycle") or {}
    counts = lifecycle.get("counts") or {}
    add("---")
    add("")
    add("## 6.1 Finding Aggregation (New / Existing / Fixed)")
    add("")
    add("| State | Count |")
    add("|---|---|")
    for label, key in (("New", "new"), ("Existing / still open", "existing"), ("Fixed", "fixed"),
                       ("False positive (suppressed)", "false_positive"),
                       ("Accepted risk (suppressed)", "accepted_risk"),
                       ("EXPIRED suppression (NOT suppressed)", "expired_exceptions"),
                       ("Unknown", "unknown")):
        add("| %s | %s |" % (label, counts.get(key, 0)))
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add("| Baseline available | %s |" % ("YES" if lifecycle.get("baseline_available") else "NO"))
    add("| Baseline source | %s |" % _escape(lifecycle.get("baseline_source") or "none"))
    add("| Baseline findings | %s |" % lifecycle.get("baseline_finding_count", 0))
    add("| Exceptions loaded | %s |" % lifecycle.get("exceptions_loaded", 0))
    add("")
    for note in lifecycle.get("notes") or []:
        add("> %s" % _escape(note))
        add("")
    if lifecycle.get("expired_exception_details"):
        add("**Expired suppressions — these findings are NOT suppressed**")
        add("")
        add("| Fingerprint | Kind | Owner | Expiry | Why |")
        add("|---|---|---|---|---|")
        for item in lifecycle["expired_exception_details"]:
            add("| `%s` | %s | %s | %s | %s |" % (
                _escape(item.get("fingerprint", ""))[:16], _escape(item.get("kind")),
                _escape(item.get("owner") or "-"), _escape(item.get("expires") or "none"),
                _escape(item.get("why"))))
        add("")
    if lifecycle.get("fixed_findings"):
        add("**Fixed since baseline**")
        add("")
        add("| Severity | Tool | File | Description |")
        add("|---|---|---|---|")
        for item in lifecycle["fixed_findings"][:40]:
            add("| %s | %s | %s | %s |" % (
                _escape(item.get("severity")), _escape(item.get("tool")),
                _truncate(item.get("file"), 50), _truncate(item.get("description"), 70)))
        add("")

    # --- Exploitability -------------------------------------------------------
    add("---")
    add("")
    add("## 6.2 Exploitability (EPSS / CISA KEV)")
    add("")
    enrichment = report.get("enrichment") or {}
    add("| Source | State |")
    add("|---|---|")
    add("| EPSS (exploit probability) | `%s` |" % _escape(enrichment.get("epss_status", "EPSS_DISABLED")))
    add("| CISA KEV (known exploited) | `%s` |" % _escape(enrichment.get("kev_status", "KEV_DISABLED")))
    add("")
    add("%s" % _escape(enrichment.get("statement", "")))
    add("")

    if enrichment.get("kev_status") == "KEV_AVAILABLE":
        kev_items = [f for f in findings["items"] if f.get("kev_listed")]
        if kev_items:
            add("### Known-exploited vulnerabilities present")
            add("")
            add("> These CVEs appear in CISA's catalogue of vulnerabilities with **confirmed "
                "exploitation in the wild**. This is observed fact, not a prediction.")
            add("")
            add("| Severity | CVE | EPSS | Added to KEV | File | Description |")
            add("|---|---|---|---|---|---|")
            for item in kev_items[:50]:
                score = item.get("epss_score")
                add("| %s | %s | %s | %s | `%s` | %s |" % (
                    _escape(item.get("severity")),
                    _escape("; ".join(item.get("cve_ids") or [])),
                    ("%.4f" % score) if isinstance(score, float) else "NOT_ESTABLISHED",
                    _escape(item.get("kev_date_added", "")),
                    _escape(_truncate(item.get("file"), 40)),
                    _escape(_truncate(item.get("description"), 60)),
                ))
            add("")
        else:
            add("No finding in this run matches a vulnerability in the CISA KEV catalogue.")
            add("")
    else:
        add("> Known-exploited status is **NOT_ESTABLISHED** for every finding in this run. "
            "This is absence of data, not evidence that none of these findings is being "
            "exploited.")
        add("")

    # --- Cross-scanner corroboration -----------------------------------------
    correlation = report.get("correlation") or {}
    groups = correlation.get("groups") or []
    if groups:
        add("---")
        add("")
        add("## 6.3 Cross-Scanner Corroboration")
        add("")
        add("%s" % _escape(correlation.get("statement", "")))
        add("")
        add("| File | CWE | Detected by | Lines | Severities |")
        add("|---|---|---|---|---|")
        for group in groups[:60]:
            add("| `%s` | %s | **%s** | %s | %s |" % (
                _escape(_truncate(group.get("file"), 44)),
                _escape(group.get("cwe", "")),
                _escape(" + ".join(group.get("tools") or [])),
                _escape(", ".join(str(n) for n in group.get("lines") or [])),
                _escape(", ".join(group.get("severities") or [])),
            ))
        add("")
        for note in correlation.get("notes") or []:
            add("> %s" % _escape(note))
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
        shown = items[:table_limit]
        add("| # | Severity | State | Category | Tool | File | Line | Description |")
        add("|---|---|---|---|---|---|---|---|")
        for index, finding in enumerate(shown, 1):
            add("| %d | %s | %s | %s | %s | %s | %s | %s |" % (
                index, finding["severity"], finding.get("lifecycle", "-"), finding["category"],
                _escape(finding.get("tool")), _truncate(finding["file"], 46) or "-",
                finding["line"] or "-", _truncate(finding["description"], 80),
            ))
        add("")
        if len(items) > table_limit:
            add("> Table truncated to %d of %d findings. **The complete, untruncated list is in "
                "`findings.csv`** (one row per finding, sortable, with an empty owner column), "
                "and in `final-report.json` / `normalized-findings.json`. Raise "
                "`--max-table-rows` to show more here."
                % (table_limit, len(items)))
            add("")

        add("### Finding detail")
        add("")
        for index, finding in enumerate(items[:detail_limit], 1):
            add("#### %d. [%s] %s" % (index, finding["severity"], _truncate(finding["description"], 110)))
            add("")
            add("| Field | Value |")
            add("|---|---|")
            add("| Fingerprint | `%s` |" % finding["fingerprint"])
            add("| Lifecycle state | %s |" % _escape(finding.get("lifecycle")))
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
        if len(items) > detail_limit:
            add("> Detailed entries truncated to the %d most severe of %d findings. Every "
                "finding, with the same fields, is in `findings.csv`. Raise "
                "`--max-detailed-findings` to show more here."
                % (detail_limit, len(items)))
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

    # --- File coverage --------------------------------------------------------
    # Section 8 says which CONTROLS ran. This says which FILES they read, which
    # is the question a category status cannot answer: a scanner that completed
    # over half the repository reports identically to one that read all of it.
    add("### 8.1 File Coverage")
    add("")
    coverage = report.get("file_coverage") or {}
    if not coverage.get("available"):
        add("> **File-level coverage is NOT ESTABLISHED for this run.** %s"
            % _escape(coverage.get("reason", "the census did not run")))
        add(">")
        add("> This is not a statement that every file was analysed.")
        add("")
    else:
        add("| Measure | Value |")
        add("|---|---|")
        add("| Code files in workspace | %d |" % coverage.get("code_files", 0))
        add("| Read by a completed scanner | %d |" % coverage.get("code_files_analysed", 0))
        add("| **NOT read by any scanner** | **%d** |" % coverage.get("code_files_not_analysed", 0))
        add("| Coverage | %.1f%% |" % coverage.get("coverage_percent", 0.0))
        add("")
        add("**%s**" % _escape(coverage.get("statement", "")))
        add("")

        # --- Per-scanner reach ------------------------------------------
        # The aggregate above answers "did anything miss every scanner?".
        # This answers "what did THIS scanner actually look at?", which is the
        # question asked whenever a finding is absent and someone needs to know
        # whether it was ever looked for.
        per_scanner = coverage.get("per_scanner") or []
        if per_scanner:
            add("**Coverage by scanner**")
            add("")
            add("| Scanner | Category | Status | Analysed | Excluded | Outside its file types | Not analysed |")
            add("|---|---|---|---:|---:|---:|---:|")
            for row in per_scanner:
                if row.get("file_level", True):
                    numbers = "%d | %d | %d | %d" % (
                        row.get("analysed", 0), row.get("excluded", 0),
                        row.get("outside_capability", 0), row.get("not_analysed", 0),
                    )
                else:
                    # No declared file-level reach: the honest cell is "not
                    # established", never a zero that reads as "nothing missed".
                    numbers = "n/a | n/a | n/a | n/a"
                add("| `%s` | `%s` | `%s` | %s |" % (
                    _escape(row.get("tool", "")),
                    _escape(row.get("category", "")),
                    _escape(row.get("status", "")),
                    numbers,
                ))
            add("")

            for row in per_scanner:
                add("- %s" % _escape(row.get("statement", "")))
            add("")

            unavailable = coverage.get("scanners_unavailable") or []
            failed = coverage.get("scanners_failed") or []
            if unavailable:
                add("> **Scanners NOT AVAILABLE on this runner:** %s"
                    % ", ".join("`%s`" % _escape(t) for t in unavailable))
                add(">")
                add("> Their categories are NOT_VERIFIED. Absence of findings from these "
                    "scanners is not evidence that no such finding exists.")
                add("")
            if failed:
                add("> **Scanners that did NOT complete:** %s"
                    % ", ".join("`%s`" % _escape(t) for t in failed))
                add("")

        not_analysed = coverage.get("not_analysed") or {}
        if not_analysed:
            add("| Reason not analysed | Files |")
            add("|---|---|")
            for bucket, detail in not_analysed.items():
                add("| `%s` | %d |" % (_escape(bucket), detail.get("count", 0)))
            add("")
            for bucket, detail in not_analysed.items():
                shown = detail.get("files") or []
                if not shown:
                    continue
                add("<details><summary>%s -- %d file(s), showing %d</summary>"
                    % (_escape(bucket), detail.get("count", 0), len(shown)))
                add("")
                for entry in shown:
                    add("- `%s` -- %s" % (_escape(entry.get("file")), _escape(entry.get("reason"))))
                add("")
                add("</details>")
                add("")

        for note in coverage.get("notes") or []:
            add("> %s" % _escape(note))
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


def write_markdown(
    report: Dict[str, Any],
    output_dir: str,
    filename: str = "report.md",
    max_table_rows: Optional[int] = None,
    max_detailed: Optional[int] = None,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(report, max_table_rows, max_detailed))
    return path
