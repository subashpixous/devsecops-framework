"""Web server configuration -> common Finding schema.

Every issue from this collector is a *misconfiguration*: the application source
may be correct and the exposure still real, because the server was told to
behave this way. They are mapped to the `misconfiguration` policy category so
they count against the same thresholds as any other misconfiguration, and to the
CWE that names the specific exposure rather than a generic one.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "web-config"
CATEGORY_KEY = "web_server_config"

RULE_MAP: Dict[str, Any] = {
    "upload-directory-executes-code": ("CWE-434", "A03:2021-Injection"),
    "directory-listing-enabled": ("CWE-548", "A01:2021-Broken Access Control"),
    "directory-listing-ambiguous": ("CWE-548", "A05:2021-Security Misconfiguration"),
    "server-version-disclosed": ("CWE-200", "A05:2021-Security Misconfiguration"),
    "sensitive-extensions-not-denied": ("CWE-538", "A05:2021-Security Misconfiguration"),
}

DEFAULT_MAP = ("", "A05:2021-Security Misconfiguration")


class WebConfigAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status != "FAILED":
                result.fail(
                    "Web server configuration produced no payload; no directive was reviewed. "
                    "An empty result here must not read as a clean one."
                )
            return []

        issues = payload.get("issues")
        if issues is None:
            result.fail(
                "Web server configuration payload contains no 'issues' array; output cannot be trusted."
            )
            return []

        findings: List[Finding] = []
        for issue in issues:
            try:
                findings.append(self._to_finding(issue, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed web server configuration record: %s" % exc)
        return findings

    def _to_finding(self, issue: Dict[str, Any], context: RunContext) -> Finding:
        rule = issue.get("rule") or "web-config"
        cwe, owasp = RULE_MAP.get(rule, DEFAULT_MAP)
        path = issue.get("file") or ""
        title = issue.get("title") or rule
        detail = issue.get("description") or ""

        return self.stamp(
            Finding(
                tool=TOOL,
                category="misconfiguration",
                severity=str(issue.get("severity") or "MEDIUM"),
                cwe=cwe,
                owasp=owasp,
                file=path,
                line=0,
                evidence="directive review of %s" % (path or "<unknown file>"),
                description="%s. %s" % (title.rstrip("."), detail) if detail else title,
                impact=issue.get("impact") or "",
                remediation=issue.get("remediation") or "",
                rule=rule,
                scanner_category=CATEGORY_KEY,
                tags=["web-config", rule],
            ),
            context,
        )
