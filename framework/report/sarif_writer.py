"""SARIF 2.1.0 output — the format that puts findings where developers are.

A finding in a downloadable PDF is a finding nobody reads. SARIF is what GitHub
code scanning consumes, and uploading it puts every finding on the exact line of
the exact file in the pull request that introduced it, plus the repository's
Security tab, with history across runs.

Two properties of this file are load-bearing:

  * `partialFingerprints` carries the framework's own fingerprint, so GitHub
    tracks a finding across runs even when the line it sits on moves. Without it
    every reformat re-raises every finding as new.
  * `suppressions` carries accepted-risk and false-positive states from the
    lifecycle engine, so a decision already made in `exceptions.yml` is not
    re-litigated in the pull request. An EXPIRED exception is deliberately NOT
    suppressed -- that is the whole point of expiry.

Nothing is invented here. A finding with no file location is emitted against the
repository root with its location stated as unknown, rather than dropped: a
finding that vanishes because it has no line number is a silent gap.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has three actionable levels plus "none". Mapping is deliberately blunt:
# CRITICAL and HIGH are errors that should block, everything else is visible but
# does not fail a check by itself.
LEVEL_BY_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    # An unclassifiable finding is NOT downgraded to a note. The policy fails
    # UNKNOWN closed at zero, and this file must not contradict that.
    "UNKNOWN": "warning",
}

# GitHub's security-severity drives the CVSS-style band shown in the Security
# tab and the alert-level filters teams build their triage rules on.
SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "INFO": "1.0",
    "UNKNOWN": "5.0",
}

# Lifecycle states that represent a decision already taken and recorded.
SUPPRESSED_LIFECYCLE = {"FALSE_POSITIVE", "ACCEPTED_RISK"}


def _rule_id(finding: Dict[str, Any]) -> str:
    """Stable rule identity: the tool's own rule where it has one.

    Prefixed with the tool so two engines that both ship a rule called
    `sql-injection` do not collapse into one entry in the Security tab.
    """
    tool = str(finding.get("tool") or "unknown").strip() or "unknown"
    rule = str(finding.get("rule") or "").strip()
    if not rule:
        rule = str(finding.get("category") or "finding").strip() or "finding"
    return "%s/%s" % (tool, rule)


def _uri(path: str) -> str:
    """Repository-relative POSIX path, which is what code scanning matches on."""
    text = str(path or "").replace("\\", "/").lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _location(finding: Dict[str, Any]) -> Dict[str, Any]:
    path = _uri(finding.get("file") or "")
    if not path:
        # No file: anchor to the repository so the finding still appears. A
        # finding dropped for lack of a line number is a gap, not tidiness.
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": ".", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1},
            },
            "message": {"text": "This finding is not attributed to a specific file."},
        }
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    # SARIF regions are 1-based; line 0 means "the file, line unknown".
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line if line > 0 else 1},
        }
    }


def _full_description(finding: Dict[str, Any]) -> str:
    """Everything a developer needs to act, assembled in fix order."""
    parts: List[str] = []
    description = str(finding.get("description") or "").strip()
    if description:
        parts.append(description)
    impact = str(finding.get("impact") or "").strip()
    if impact:
        parts.append("Impact: %s" % impact)
    remediation = str(finding.get("remediation") or "").strip()
    if remediation:
        parts.append("Remediation: %s" % remediation)
    evidence = str(finding.get("evidence") or "").strip()
    if evidence:
        parts.append("Evidence: %s" % evidence)
    return "\n\n".join(parts) or "No description was supplied by the scanner."


def _build_rules(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One rule descriptor per distinct rule, in first-seen order."""
    rules: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        tags = ["security", str(finding.get("category") or "finding")]
        cwe = str(finding.get("cwe") or "").strip()
        owasp = str(finding.get("owasp") or "").strip()
        if cwe:
            tags.append("external/cwe/%s" % cwe.lower())
        if owasp:
            tags.append(owasp)
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id.replace("/", "_"),
            "shortDescription": {"text": _short(finding)},
            "fullDescription": {"text": _full_description(finding)},
            "defaultConfiguration": {"level": LEVEL_BY_SEVERITY.get(severity, "warning")},
            "properties": {
                "tags": tags,
                "security-severity": SECURITY_SEVERITY.get(severity, "5.0"),
                "precision": "high" if severity in ("CRITICAL", "HIGH") else "medium",
            },
        }
        remediation = str(finding.get("remediation") or "").strip()
        if remediation:
            rules[rule_id]["help"] = {"text": remediation}
    return list(rules.values())


def _short(finding: Dict[str, Any]) -> str:
    text = str(finding.get("description") or "").strip()
    if not text:
        return str(finding.get("rule") or finding.get("category") or "Security finding")
    # First sentence, capped: the Security tab shows this in a list.
    head = text.split(". ")[0].strip()
    return (head[:117] + "...") if len(head) > 120 else head


def _suppression(finding: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Accepted-risk / false-positive states, as recorded by the lifecycle engine.

    EXPIRED is intentionally absent: an exception past its review date does not
    suppress anything, and emitting one here would quietly restore a suppression
    the policy just revoked.
    """
    lifecycle = str(finding.get("lifecycle") or "").upper()
    if lifecycle not in SUPPRESSED_LIFECYCLE:
        return None
    justification = str(finding.get("exception_reason") or "").strip() or \
        "Suppressed by a recorded exception."
    expires = str(finding.get("exception_expires") or "").strip()
    if expires:
        justification += " Expires %s." % expires
    return [{
        "kind": "external",
        "status": "accepted",
        "justification": justification,
    }]


def build_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble a SARIF log from a completed framework report."""
    findings = list((report.get("findings") or {}).get("items") or [])
    framework = report.get("framework") or {}
    version = str(framework.get("version") or "0.0.0")

    results: List[Dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        result: Dict[str, Any] = {
            "ruleId": _rule_id(finding),
            "level": LEVEL_BY_SEVERITY.get(severity, "warning"),
            "message": {"text": _full_description(finding)},
            "locations": [_location(finding)],
            "partialFingerprints": {
                # Framework-owned identity. Keeps a finding the same alert across
                # runs even when the code around it moves.
                "devsecopsFrameworkFingerprint/v1": str(finding.get("fingerprint") or ""),
            },
            "properties": {
                "tool": finding.get("tool"),
                "category": finding.get("category"),
                "scanner_category": finding.get("scanner_category"),
                "severity": severity,
                "lifecycle": finding.get("lifecycle"),
                "cwe": finding.get("cwe"),
                "owasp": finding.get("owasp"),
                "first_seen": finding.get("first_seen"),
            },
        }
        suppression = _suppression(finding)
        if suppression:
            result["suppressions"] = suppression
        results.append(result)

    # Invocation records whether this run is complete. A SARIF file from a run
    # whose scanners failed must not look like a clean scan of everything.
    status = report.get("status") or {}
    coverage = report.get("file_coverage") or {}
    notifications = []
    if not status.get("coverage_complete", True):
        notifications.append({
            "level": "warning",
            "message": {"text": (
                "Security coverage for this run is INCOMPLETE. Categories reported "
                "NOT_VERIFIED or NOT_IMPLEMENTED; their findings, if any, are absent from "
                "this file. Absence of a result here is not evidence of absence of a defect."
            )},
            "descriptor": {"id": "coverage/incomplete"},
        })
    if coverage.get("available") and not coverage.get("complete", True):
        notifications.append({
            "level": "warning",
            "message": {"text": coverage.get("statement") or "Some files were not analysed."},
            "descriptor": {"id": "coverage/files-not-analysed"},
        })

    invocation: Dict[str, Any] = {
        # The run "succeeded" as an execution; whether it verified anything is
        # carried by the notifications above and by the report's own verdict.
        "executionSuccessful": True,
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DevSecOps Framework",
                    "informationUri": "https://github.com/",
                    "semanticVersion": version,
                    "version": version,
                    "rules": _build_rules(findings),
                }
            },
            "invocations": [invocation],
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }


def write_sarif(report: Dict[str, Any], output_dir: str, filename: str = "security.sarif") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_sarif(report), handle, indent=2)
        handle.write("\n")
    return path
