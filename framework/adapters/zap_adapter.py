"""OWASP ZAP -> common Finding schema."""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "owasp-zap"
CATEGORY_KEY = "dast_zap"

# ZAP riskcode: 0 informational, 1 low, 2 medium, 3 high.
RISK_MAP = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}

_TAGS = re.compile(r"<[^>]+>")


def _plain(text: Any, limit: int = 600) -> str:
    """ZAP descriptions are HTML fragments; flatten them for the schema."""
    value = _TAGS.sub(" ", str(text or ""))
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


class ZapAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("ZAP payload was empty; findings could not be normalised.")
            return []

        sites = payload.get("site")
        if sites is None:
            result.fail("ZAP payload contains no 'site' section; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for site in sites:
            site_name = site.get("@name") or payload.get("_target") or ""
            for alert in site.get("alerts") or []:
                try:
                    findings.append(self._to_finding(alert, site_name, context))
                except Exception as exc:  # noqa: BLE001
                    result.partial("Skipped a malformed ZAP alert: %s" % exc)
        return findings

    def _to_finding(self, alert: Dict[str, Any], site: str, context: RunContext) -> Finding:
        instances = alert.get("instances") or []
        first = instances[0] if instances else {}
        uri = first.get("uri") or site
        method = first.get("method") or ""
        param = first.get("param") or ""
        cwe_id = str(alert.get("cweid") or "").strip()

        evidence = ["endpoint=%s" % uri]
        if method:
            evidence.append("method=%s" % method)
        if param:
            evidence.append("param=%s" % param)
        evidence.append("instances=%d" % len(instances))
        evidence.append("confidence=%s" % (alert.get("confidence") or "?"))
        # first.get("evidence") deliberately omitted: it echoes response content,
        # which can contain tokens or personal data.

        return self.stamp(
            Finding(
                tool=TOOL,
                category="dast_finding",
                severity=RISK_MAP.get(str(alert.get("riskcode")), "UNKNOWN"),
                raw_severity=str(alert.get("riskdesc") or ""),
                cwe="CWE-%s" % cwe_id if cwe_id and cwe_id != "-1" else "",
                owasp="",
                file="",
                line=0,
                endpoint=uri,
                evidence=" | ".join(evidence),
                description=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                impact=_plain(alert.get("desc")) or "Dynamic scan identified this issue against the running application.",
                remediation=_plain(alert.get("solution")) or "See the ZAP alert reference for remediation guidance.",
                rule=str(alert.get("pluginid") or ""),
                native_id=str(alert.get("alertRef") or alert.get("pluginid") or ""),
                component=uri,
                phase=5,
                scanner_category=CATEGORY_KEY,
            ),
            context,
        )
