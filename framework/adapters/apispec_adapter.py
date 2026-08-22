"""42Crunch -> common Finding schema."""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "42crunch"
CATEGORY_KEY = "api_spec_security"

# 42Crunch scores 0-100; lower is worse.
def _severity_from_score(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if value < 30:
        return "CRITICAL"
    if value < 50:
        return "HIGH"
    if value < 75:
        return "MEDIUM"
    return "LOW"


class ApiSpecAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("42Crunch payload was empty; findings could not be normalised.")
            return []

        audits = payload.get("audits")
        if audits is None:
            result.fail("42Crunch payload contains no 'audits' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for audit in audits:
            spec = audit.get("spec", "")
            report = audit.get("report") or {}
            try:
                findings.extend(self._audit_to_findings(spec, report, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed 42Crunch audit for %s: %s" % (spec, exc))
        return findings

    def _audit_to_findings(self, spec: str, report: Dict[str, Any], context: RunContext) -> List[Finding]:
        findings: List[Finding] = []

        # Overall contract score.
        score = report.get("score", report.get("apiScore"))
        if score is not None:
            findings.append(
                self.stamp(
                    Finding(
                        tool=TOOL, category="api_spec_finding",
                        severity=_severity_from_score(score), raw_severity=str(score),
                        cwe="", owasp="A4:2021", file=spec, line=0,
                        evidence="%s | overall_score=%s" % (spec, score),
                        description="OpenAPI contract security score is %s/100" % score,
                        impact="A low contract score indicates the specification permits insecure "
                               "request/response shapes, weak authentication definitions, or "
                               "unconstrained data types that the implementation will inherit.",
                        remediation="Address the specification issues listed by 42Crunch, "
                                    "prioritising authentication and data-constraint definitions.",
                        rule="42c.overall_score", component=spec, phase=5,
                        scanner_category=CATEGORY_KEY,
                    ),
                    context,
                )
            )

        # Individual issues; 42Crunch nests these under several possible keys.
        issues = report.get("issues") or report.get("findings") or []
        if isinstance(issues, dict):
            issues = [dict(v, id=k) for k, v in issues.items()]

        for issue in issues:
            if not isinstance(issue, dict):
                continue
            issue_id = issue.get("id") or issue.get("issueId") or ""
            pointer = issue.get("pointer") or issue.get("path") or ""
            criticality = issue.get("criticality")
            findings.append(
                self.stamp(
                    Finding(
                        tool=TOOL, category="api_spec_finding",
                        severity=normalise_severity(
                            {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO"}.get(criticality)
                            or issue.get("severity")
                        ),
                        raw_severity=str(criticality or issue.get("severity") or ""),
                        cwe="", owasp="A4:2021", file=spec, line=0,
                        endpoint=str(pointer),
                        evidence="%s | pointer=%s | issue=%s" % (spec, pointer or "<root>", issue_id or "<none>"),
                        description=str(issue.get("description") or issue.get("title") or issue_id),
                        impact=str(issue.get("impact") or
                                   "The API contract permits behaviour that weakens the security of "
                                   "every implementation generated from or validated against it."),
                        remediation=str(issue.get("remediation") or
                                        "Correct the specification at the indicated JSON pointer."),
                        rule=str(issue_id), native_id=str(issue_id),
                        component=spec, phase=5, scanner_category=CATEGORY_KEY,
                    ),
                    context,
                )
            )
        return findings
