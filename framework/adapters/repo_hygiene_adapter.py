"""Repository hygiene -> common Finding schema.

The collector emits issues that already carry their severity, impact and
remediation, because the reasoning behind each one is specific to what the file
is rather than to a rule id. This adapter maps them onto the schema and assigns
the policy `category`, which is what the status engine evaluates.

Two categories are used, deliberately:

  * `information_disclosure` for logs, dumps and archives reachable over HTTP --
    the exposure is that an outsider can read internal detail;
  * `sensitive_data_exposure` for committed personal data and credential files --
    the exposure has already happened to everyone with repository access, and no
    fix at the web server changes that.

Keeping them apart matters because the remediations are unrelated: one is fixed
by moving a file, the other by rotating a secret or reporting a breach.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "repo-hygiene"
CATEGORY_KEY = "repo_hygiene"

# Rule -> (policy category, CWE, OWASP). CWEs are the ones that describe the
# exposure itself, not the coding mistake that allowed it.
RULE_MAP: Dict[str, Any] = {
    "missing-gitignore": ("misconfiguration", "CWE-1188", "A05:2021-Security Misconfiguration"),
    "committed-runtime-log-in-webroot": ("information_disclosure", "CWE-532", "A09:2021-Security Logging and Monitoring Failures"),
    "committed-runtime-log": ("information_disclosure", "CWE-532", "A09:2021-Security Logging and Monitoring Failures"),
    "database-file-in-webroot": ("information_disclosure", "CWE-538", "A01:2021-Broken Access Control"),
    "environment-file-committed": ("sensitive_data_exposure", "CWE-538", "A05:2021-Security Misconfiguration"),
    "key-material-committed": ("sensitive_data_exposure", "CWE-798", "A07:2021-Identification and Authentication Failures"),
    "user-uploaded-documents-committed": ("sensitive_data_exposure", "CWE-359", "A01:2021-Broken Access Control"),
    "archive-in-webroot": ("information_disclosure", "CWE-538", "A01:2021-Broken Access Control"),
}

DEFAULT_MAP = ("misconfiguration", "", "A05:2021-Security Misconfiguration")


class RepoHygieneAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status != "FAILED":
                result.fail(
                    "Repository hygiene produced no payload; the repository was NOT assessed. "
                    "An empty result here must not read as a clean one."
                )
            return []

        issues = payload.get("issues")
        if issues is None:
            result.fail("Repository hygiene payload contains no 'issues' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for issue in issues:
            try:
                findings.append(self._to_finding(issue, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed repository hygiene record: %s" % exc)
        return findings

    def _to_finding(self, issue: Dict[str, Any], context: RunContext) -> Finding:
        rule = issue.get("rule") or "repo-hygiene"
        category, cwe, owasp = RULE_MAP.get(rule, DEFAULT_MAP)
        path = issue.get("file") or ""
        count = int(issue.get("count") or 1)

        # Evidence names the path and the scale, never the contents and -- for
        # user submissions -- never the individual filenames.
        evidence = "tracked in git: %s" % (path or "<repository root>")
        if count > 1:
            evidence += " (%d files)" % count

        # Title first so the findings TABLE, which truncates, still reads as a
        # sentence; the explanation follows for the detail entry.
        title = issue.get("title") or rule
        detail = issue.get("description") or ""
        description = "%s. %s" % (title.rstrip("."), detail) if detail else title

        return self.stamp(
            Finding(
                tool=TOOL,
                category=category,
                severity=str(issue.get("severity") or "MEDIUM"),
                cwe=cwe,
                owasp=owasp,
                file=path,
                line=0,
                evidence=evidence,
                description=description,
                impact=issue.get("impact") or "",
                remediation=issue.get("remediation") or "",
                rule=rule,
                scanner_category=CATEGORY_KEY,
                tags=["repo-hygiene", rule],
            ),
            context,
        )
