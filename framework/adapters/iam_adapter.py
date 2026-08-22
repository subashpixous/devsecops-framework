"""AWS IAM Access Analyzer -> common Finding schema."""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "aws-iam-access-analyzer"
CATEGORY_KEY = "iam_access_analyzer"

# Public access is materially worse than cross-account access to a known principal.
def _severity(finding: Dict[str, Any]) -> str:
    if finding.get("isPublic"):
        return "HIGH"
    return "MEDIUM"


class IamAccessAnalyzerAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("IAM Access Analyzer payload was empty; findings could not be normalised.")
            return []

        region = payload.get("_region", "")
        findings: List[Finding] = []

        # The control being absent is itself reportable.
        if payload.get("no_analyzer_configured"):
            findings.append(
                self.stamp(
                    Finding(
                        tool=TOOL,
                        category="cloud_misconfiguration",
                        severity="MEDIUM",
                        cwe="CWE-284",
                        owasp="A1:2021",
                        component="account:%s" % (region or "unknown-region"),
                        evidence="region=%s | no ACTIVE analyzer" % region,
                        description="No IAM Access Analyzer is configured in region %s" % region,
                        impact=(
                            "Without an analyzer, AWS is not evaluating which resources are shared "
                            "outside the account. Unintended external access would go undetected."
                        ),
                        remediation=(
                            "Create an account-level IAM Access Analyzer in each region in use and "
                            "review its findings regularly."
                        ),
                        rule="iam.no_analyzer_configured",
                        phase=6,
                        scanner_category=CATEGORY_KEY,
                    ),
                    context,
                )
            )
            return findings

        records = payload.get("findings")
        if records is None:
            result.fail("IAM Access Analyzer payload contains no 'findings' array; output cannot be trusted.")
            return []

        for record in records:
            if str(record.get("status", "")).upper() != "ACTIVE":
                continue
            try:
                findings.append(self._to_finding(record, region, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed IAM Access Analyzer record: %s" % exc)
        return findings

    def _to_finding(self, record: Dict[str, Any], region: str, context: RunContext) -> Finding:
        resource = record.get("resource") or ""
        resource_type = record.get("resourceType") or ""
        principal = record.get("principal") or {}
        actions = record.get("action") or []
        is_public = bool(record.get("isPublic"))

        principal_desc = "PUBLIC (everyone)" if is_public else ", ".join(
            "%s=%s" % (k, v) for k, v in principal.items()
        ) or "external principal"

        evidence = [
            "resource=%s" % resource,
            "type=%s" % resource_type,
            "principal=%s" % principal_desc,
            "region=%s" % region,
        ]
        if actions:
            evidence.append("actions=%s" % ",".join(str(a) for a in actions[:8]))

        return self.stamp(
            Finding(
                tool=TOOL,
                category="cloud_misconfiguration",
                severity=_severity(record),
                raw_severity="public" if is_public else "external",
                cwe="CWE-284",
                owasp="A1:2021",
                component=resource,
                evidence=" | ".join(evidence),
                description="%s %s is accessible to %s"
                            % (resource_type or "Resource", resource, principal_desc),
                impact=(
                    "This resource grants access outside the account boundary. Public exposure "
                    "means any AWS principal, or anyone at all, can reach it."
                    if is_public else
                    "This resource grants access to a principal outside the account. Confirm the "
                    "trust relationship is intended and scoped to the minimum required actions."
                ),
                remediation=(
                    "Review the resource policy and remove the external grant, or narrow it to the "
                    "specific principal and actions required. Archive the finding in Access "
                    "Analyzer only once the access is confirmed intentional."
                ),
                rule="iam.external_access",
                native_id=str(record.get("id") or ""),
                first_seen=str(record.get("createdAt") or ""),
                last_seen=str(record.get("updatedAt") or ""),
                phase=6,
                scanner_category=CATEGORY_KEY,
            ),
            context,
        )
