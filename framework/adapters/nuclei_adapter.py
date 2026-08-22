"""Nuclei -> common Finding schema."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "nuclei"
CATEGORY_KEY = "nuclei_templates"

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class NucleiAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Nuclei payload was empty; findings could not be normalised.")
            return []

        records = payload.get("findings")
        if records is None:
            result.fail("Nuclei payload contains no 'findings' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for record in records:
            try:
                findings.append(self._to_finding(record, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed Nuclei record: %s" % exc)
        return findings

    def _to_finding(self, record: Dict[str, Any], context: RunContext) -> Finding:
        info = record.get("info") or {}
        template_id = record.get("template-id") or record.get("templateID") or ""
        matched = record.get("matched-at") or record.get("host") or ""
        name = info.get("name") or template_id
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        classification = info.get("classification") or {}
        cwe_ids = classification.get("cwe-id") or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        cwes = sorted({("CWE-%s" % m.group(1)) for c in cwe_ids for m in [_CWE.search(str(c))] if m})

        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cves = sorted({str(c).upper() for c in cve_ids if _CVE.match(str(c))})
        if not cves:
            cves = sorted({m.group(0).upper() for m in _CVE.finditer(template_id)})

        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        evidence = ["endpoint=%s" % matched, "template=%s" % template_id]
        if record.get("type"):
            evidence.append("protocol=%s" % record["type"])
        if cves:
            evidence.append("cve=%s" % ",".join(cves))
        if tags:
            evidence.append("tags=%s" % ",".join(tags[:6]))
        # record["extracted-results"] / "response" deliberately omitted: they echo
        # live response content, which may contain tokens or personal data.

        remediation = info.get("remediation") or (
            "Review the Nuclei template %s and remediate the exposure it identifies." % template_id
        )
        if references:
            remediation += " References: %s" % ", ".join(str(r) for r in references[:3])

        return self.stamp(
            Finding(
                tool=TOOL,
                category="dast_finding",
                severity=normalise_severity(info.get("severity")),
                raw_severity=str(info.get("severity") or ""),
                cwe=", ".join(cwes),
                owasp="",
                file="",
                line=0,
                endpoint=matched,
                evidence=" | ".join(evidence),
                description=str(name),
                impact=str(info.get("description") or "")[:600]
                or "A known exposure was detected on the live target by template matching.",
                remediation=remediation[:600],
                rule=template_id,
                native_id=template_id,
                component=matched,
                tags=[str(t) for t in tags],
                phase=5,
                scanner_category=CATEGORY_KEY,
            ),
            context,
        )
