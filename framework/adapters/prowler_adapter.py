"""Prowler (OCSF) -> common Finding schema.

Only FAIL findings become schema findings; PASS results are counted but not
emitted, so the report is not flooded with controls that are already correct.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "prowler"
CATEGORY_KEY = "cloud_posture"


def _get(record: Dict[str, Any], *path: str, default: Any = "") -> Any:
    node: Any = record
    for key in path:
        if not isinstance(node, dict):
            return default
        node = node.get(key)
        if node is None:
            return default
    return node


class ProwlerAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Prowler payload was empty; findings could not be normalised.")
            return []

        records = payload.get("findings")
        if records is None:
            result.fail("Prowler payload contains no 'findings' array; output cannot be trusted.")
            return []

        provider = payload.get("_provider", "")
        findings: List[Finding] = []
        passed = 0

        for record in records:
            if not isinstance(record, dict):
                continue
            status = str(
                record.get("status_code") or _get(record, "status_code") or record.get("Status") or ""
            ).upper()
            if status not in ("FAIL", "FAILED", "NEW"):
                passed += 1
                continue
            try:
                findings.append(self._to_finding(record, provider, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed Prowler record: %s" % exc)

        result.metadata["passed_controls"] = passed
        return findings

    def _to_finding(self, record: Dict[str, Any], provider: str, context: RunContext) -> Finding:
        # OCSF shape, with tolerant fallbacks for Prowler's native shape.
        check_id = (
            _get(record, "metadata", "event_code")
            or record.get("check_id")
            or record.get("CheckID")
            or ""
        )
        title = record.get("finding_info", {}).get("title") if isinstance(record.get("finding_info"), dict) else None
        title = title or record.get("check_title") or record.get("CheckTitle") or check_id
        severity = record.get("severity") or record.get("Severity") or ""
        risk = record.get("risk_details") or record.get("Risk") or ""
        remediation = (
            _get(record, "remediation", "desc")
            or _get(record, "Remediation", "Recommendation", "Text")
            or record.get("remediation_recommendation_text")
            or ""
        )
        resources = record.get("resources") or []
        resource_uid = ""
        resource_type = ""
        region = record.get("cloud", {}).get("region", "") if isinstance(record.get("cloud"), dict) else ""
        if resources and isinstance(resources[0], dict):
            resource_uid = resources[0].get("uid") or resources[0].get("name") or ""
            resource_type = resources[0].get("type") or ""

        evidence = ["provider=%s" % (provider or "?"), "check=%s" % (check_id or "<none>")]
        if resource_uid:
            evidence.append("resource=%s" % resource_uid)
        if resource_type:
            evidence.append("resource_type=%s" % resource_type)
        if region:
            evidence.append("region=%s" % region)

        return self.stamp(
            Finding(
                tool=TOOL,
                category="cloud_misconfiguration",
                severity=normalise_severity(severity),
                raw_severity=str(severity),
                cwe="",
                owasp="A5:2021",
                file="",
                line=0,
                component=resource_uid,
                evidence=" | ".join(evidence),
                description=str(title),
                impact=str(risk)[:600] or "Cloud resource configuration deviates from a security baseline control.",
                remediation=str(remediation)[:600] or "Apply the remediation described by control %s." % check_id,
                rule=str(check_id),
                native_id=str(record.get("uid") or record.get("finding_uid") or check_id),
                tags=[provider] if provider else [],
                phase=6,
                scanner_category=CATEGORY_KEY,
            ),
            context,
        )
