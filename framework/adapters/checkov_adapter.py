"""Checkov -> common Finding schema."""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "checkov"
CATEGORY_KEY = "iac_scanning"

# Checkov often omits severity in the community edition. Absent severity must not
# become INFO, so it is left to normalise to UNKNOWN, which fails closed.
GUIDELINE_FALLBACK = "Consult the Checkov policy documentation for this check ID."


class CheckovAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Checkov payload was empty; findings could not be normalised.")
            return []

        failed = payload.get("failed_checks")
        if failed is None:
            result.fail("Checkov payload contains no 'failed_checks' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for check in failed:
            try:
                findings.append(self._to_finding(check, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed Checkov record: %s" % exc)
        return findings

    def _to_finding(self, check: Dict[str, Any], context: RunContext) -> Finding:
        check_id = check.get("check_id") or ""
        name = check.get("check_name") or check_id
        path = check.get("file_path") or ""
        line_range = check.get("file_line_range") or [0, 0]
        line = line_range[0] if isinstance(line_range, list) and line_range else 0
        resource = check.get("resource") or ""
        guideline = check.get("guideline") or ""
        severity = check.get("severity")  # None on community edition

        evidence = ["%s:%s" % (path or "<unknown>", line or 0), "check=%s" % (check_id or "<none>")]
        if resource:
            evidence.append("resource=%s" % resource)
        if check.get("check_class"):
            evidence.append("class=%s" % check["check_class"])

        return self.stamp(
            Finding(
                tool=TOOL,
                category="misconfiguration",
                severity=normalise_severity(severity),
                raw_severity=str(severity or ""),
                cwe="",
                owasp="A5:2021",
                file=path,
                line=line,
                evidence=" | ".join(evidence),
                description=("%s: %s" % (check_id, name)).strip(": "),
                impact=(
                    "Infrastructure-as-code defines this resource insecurely. The weakness is "
                    "provisioned every time this template is applied, so it reappears after any "
                    "manual fix."
                ),
                remediation=guideline or GUIDELINE_FALLBACK,
                rule=check_id,
                native_id=str(check.get("check_id") or ""),
                component=resource or path,
                phase=2,
                scanner_category=CATEGORY_KEY,
            ),
            context,
        )
