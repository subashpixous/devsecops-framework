"""SonarQube -> common Finding schema.

Field mapping note: `category` carries the *class* of finding
(vulnerability / security_hotspot / bug / code_smell), which is what downstream
policy evaluates. `scanner_category` carries the framework security category key
(sast_sonarqube). Future adapters follow the same convention -- e.g. Gitleaks
emits category "secret", Trivy emits "dependency_vulnerability", ZAP emits
"dast_finding" -- so one policy vocabulary covers every tool.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import (
    Finding,
    SEVERITY_RANK,
    SEVERITY_UNKNOWN,
    STATUS_RESOLVED,
    STATUS_TO_REVIEW,
    normalise_severity,
)
from .base import Adapter

TOOL = "sonarqube"
CATEGORY_KEY = "sast_sonarqube"

TYPE_TO_CATEGORY = {
    "VULNERABILITY": "vulnerability",
    "SECURITY_HOTSPOT": "security_hotspot",
    "BUG": "bug",
    "CODE_SMELL": "code_smell",
}

_CWE_PATTERN = re.compile(r"^cwe:(\d+)$", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"^owaspTop10(?:-(\d{4}))?:a(\d+)$", re.IGNORECASE)
_OWASP_TAG_PATTERN = re.compile(r"^owasp-a(\d+)(?:-(\d{4}))?$", re.IGNORECASE)

IMPACT_BY_CATEGORY = {
    "vulnerability": (
        "SonarQube classifies this as an exploitable weakness in application code. "
        "If reachable from untrusted input it can be abused directly."
    ),
    "security_hotspot": (
        "A security-sensitive code pattern that requires human review. It is not a "
        "confirmed vulnerability, and it is not proven safe either."
    ),
    "bug": (
        "A correctness defect. Not classified as a security weakness by SonarQube, but "
        "it can still produce incorrect behaviour or availability impact."
    ),
    "code_smell": (
        "A maintainability issue. No direct security impact asserted; retained for "
        "completeness of the analysis record."
    ),
}


def _component_to_path(component: str) -> str:
    """SonarQube components are 'projectKey:relative/path'."""
    if not component:
        return ""
    _, separator, path = component.partition(":")
    return path if separator else component


def _standards_to_cwe(standards: List[str]) -> str:
    codes = []
    for item in standards or []:
        match = _CWE_PATTERN.match(str(item).strip())
        if match:
            codes.append("CWE-%s" % match.group(1))
    return ", ".join(sorted(set(codes), key=lambda c: int(c.split("-")[1])))


def _standards_to_owasp(standards: List[str], tags: List[str]) -> str:
    entries = set()
    for item in standards or []:
        match = _OWASP_PATTERN.match(str(item).strip())
        if match:
            year = match.group(1) or "2017"
            entries.add("A%s:%s" % (match.group(2), year))
    for tag in tags or []:
        match = _OWASP_TAG_PATTERN.match(str(tag).strip())
        if match:
            year = match.group(2) or "2017"
            entries.add("A%s:%s" % (match.group(1), year))
    return ", ".join(sorted(entries))


def _issue_severity(issue: Dict[str, Any]) -> str:
    """Prefer Clean Code impact severities; fall back to the legacy severity."""
    impacts = issue.get("impacts") or []
    best = None
    for impact in impacts:
        candidate = normalise_severity(impact.get("severity"))
        if candidate == SEVERITY_UNKNOWN:
            continue
        if best is None or SEVERITY_RANK[candidate] < SEVERITY_RANK[best]:
            best = candidate
    if best:
        return best
    return normalise_severity(issue.get("severity"))


def quality_gate_summary(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract the quality gate verdict and its failing conditions.

    Returns status UNKNOWN when the payload is absent or unrecognisable -- never
    OK, so a missing gate can never be read as a passing gate.
    """
    summary: Dict[str, Any] = {"status": "UNKNOWN", "conditions": [], "failing_conditions": []}
    if not payload:
        return summary

    gate = payload.get("projectStatus")
    if not isinstance(gate, dict):
        return summary

    summary["status"] = str(gate.get("status") or "UNKNOWN").upper()
    for condition in gate.get("conditions") or []:
        entry = {
            "metric": condition.get("metricKey", ""),
            "comparator": condition.get("comparator", ""),
            "threshold": condition.get("errorThreshold", ""),
            "actual": condition.get("actualValue", ""),
            "status": str(condition.get("status") or "").upper(),
        }
        summary["conditions"].append(entry)
        if entry["status"] == "ERROR":
            summary["failing_conditions"].append(entry)
    return summary


class SonarQubeAdapter(Adapter):
    """Normalises SonarQube issues and hotspots into the common schema."""

    tool = TOOL
    category_key = CATEGORY_KEY

    def summarize_gate(self, result: ScannerResult) -> Dict[str, Any]:
        payload = result.payload or {}
        return quality_gate_summary(payload.get("quality_gate"))

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            # No payload is not "no findings" -- say so on the result so the status
            # engine resolves the category to NOT_VERIFIED.
            if result.status not in ("FAILED",):
                result.fail("SonarQube payload was empty; findings could not be normalised.")
            return []

        rules: Dict[str, Any] = payload.get("rules") or {}
        findings: List[Finding] = []

        issues = payload.get("issues")
        if issues is None:
            result.fail("SonarQube payload contains no 'issues' array; results are untrustworthy.")
            issues = []

        for issue in issues:
            try:
                findings.append(self._issue_to_finding(issue, rules, context))
            except Exception as exc:  # noqa: BLE001 - one bad record must not hide the rest
                result.partial("Skipped a malformed SonarQube issue record: %s" % exc)

        for hotspot in payload.get("hotspots") or []:
            try:
                findings.append(self._hotspot_to_finding(hotspot, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed SonarQube hotspot record: %s" % exc)

        return findings

    def _issue_to_finding(
        self, issue: Dict[str, Any], rules: Dict[str, Any], context: RunContext
    ) -> Finding:
        issue_type = str(issue.get("type") or "").upper()
        category = TYPE_TO_CATEGORY.get(issue_type, "unknown")
        rule_key = issue.get("rule") or ""
        rule_meta = rules.get(rule_key) or {}
        tags = list(issue.get("tags") or [])
        standards = list(rule_meta.get("securityStandards") or [])

        file_path = _component_to_path(issue.get("component") or "")
        line = issue.get("line") or (issue.get("textRange") or {}).get("startLine") or 0
        message = issue.get("message") or ""
        rule_name = rule_meta.get("name") or ""

        evidence_parts = ["%s:%s" % (file_path or "<unknown file>", line or 0), "rule=%s" % (rule_key or "<none>")]
        if issue.get("hash"):
            evidence_parts.append("hash=%s" % issue["hash"])
        effort = issue.get("effort") or issue.get("debt") or ""

        finding = Finding(
            tool=TOOL,
            category=category,
            severity=_issue_severity(issue),
            raw_severity=str(issue.get("severity") or ""),
            cwe=_standards_to_cwe(standards),
            owasp=_standards_to_owasp(standards, tags),
            file=file_path,
            line=line,
            endpoint="",
            evidence=" | ".join(evidence_parts),
            description=("%s -- %s" % (rule_name, message)).strip(" -") if rule_name else message,
            impact=IMPACT_BY_CATEGORY.get(category, IMPACT_BY_CATEGORY["code_smell"]),
            remediation=self._remediation_text(rule_key, effort),
            first_seen=self._iso(issue.get("creationDate")),
            last_seen=self._iso(issue.get("updateDate")) or self._iso(issue.get("creationDate")),
            status=str(issue.get("status") or "OPEN").upper(),
            native_id=issue.get("key") or "",
            rule=rule_key,
            tags=tags,
            component=issue.get("component") or "",
            effort=str(effort),
            phase=1,
            scanner_category=CATEGORY_KEY,
        )
        return self.stamp(finding, context)

    def _hotspot_to_finding(self, hotspot: Dict[str, Any], context: RunContext) -> Finding:
        file_path = _component_to_path(hotspot.get("component") or "")
        line = hotspot.get("line") or 0
        message = hotspot.get("message") or ""
        rule_key = hotspot.get("ruleKey") or ""
        raw_status = str(hotspot.get("status") or "TO_REVIEW").upper()
        status = STATUS_TO_REVIEW if raw_status == "TO_REVIEW" else STATUS_RESOLVED
        security_category = hotspot.get("securityCategory") or ""

        finding = Finding(
            tool=TOOL,
            category="security_hotspot",
            severity=normalise_severity(hotspot.get("vulnerabilityProbability")),
            raw_severity=str(hotspot.get("vulnerabilityProbability") or ""),
            cwe="",
            owasp="",
            file=file_path,
            line=line,
            endpoint="",
            evidence="%s:%s | rule=%s | sonar_security_category=%s"
            % (file_path or "<unknown file>", line or 0, rule_key or "<none>", security_category or "<none>"),
            description=message,
            impact=IMPACT_BY_CATEGORY["security_hotspot"],
            remediation=(
                "Review this hotspot in SonarQube and record an explicit decision. An unreviewed "
                "hotspot is an untested control, not a passing one."
            ),
            first_seen=self._iso(hotspot.get("creationDate")),
            last_seen=self._iso(hotspot.get("updateDate")) or self._iso(hotspot.get("creationDate")),
            status=status,
            native_id=hotspot.get("key") or "",
            rule=rule_key,
            tags=[security_category] if security_category else [],
            component=hotspot.get("component") or "",
            phase=1,
            scanner_category=CATEGORY_KEY,
        )
        return self.stamp(finding, context)

    @staticmethod
    def _remediation_text(rule_key: str, effort: Any) -> str:
        base = (
            "Open rule %s in SonarQube for the rule description and compliant examples, then apply "
            "the fix in application code." % (rule_key or "<unknown>")
        )
        if effort:
            base += " SonarQube estimated remediation effort: %s." % effort
        return base

    @staticmethod
    def _iso(value: Optional[str]) -> str:
        """SonarQube emits ISO-8601 with offsets like +0000; keep as-is if present."""
        return str(value) if value else ""
