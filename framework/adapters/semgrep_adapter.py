"""Semgrep / OpenGrep -> common Finding schema.

Note on evidence: Semgrep returns the matched source text in `extra.lines`.
That text is deliberately NOT copied into the finding. Semgrep rulesets include
secret-detection rules, so the matched line can itself be a credential, and
findings end up in a downloadable artifact.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.rulepack import RULE_ID_PREFIX
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "semgrep"
CATEGORY_KEY = "sast_semgrep"

# Normalized finding categories a framework rule may declare. Constrained to the
# set the policy already scores, so a typo in a rule's metadata cannot invent a
# category the status engine has never heard of and silently drop it out of
# threshold evaluation.
KNOWN_CATEGORIES = {
    "sast_finding", "information_disclosure", "sensitive_data_exposure",
    "misconfiguration", "tls", "cors", "secret", "exposed_surface",
    "security_header", "cookie_security", "vulnerability",
}

# Semgrep severity vocabulary -> canonical scale.
SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

_CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"A(\d{1,2})[:\s\-]*(\d{4})?", re.IGNORECASE)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _extract_cwe(metadata: Dict[str, Any]) -> str:
    codes = set()
    for entry in _as_list(metadata.get("cwe")):
        for match in _CWE_PATTERN.finditer(entry):
            codes.add("CWE-%s" % match.group(1))
    return ", ".join(sorted(codes, key=lambda c: int(c.split("-")[1])))


def _extract_owasp(metadata: Dict[str, Any]) -> str:
    entries = set()
    for entry in _as_list(metadata.get("owasp")):
        match = _OWASP_PATTERN.search(entry)
        if match:
            number = match.group(1).lstrip("0") or match.group(1)
            year = match.group(2) or "2021"
            entries.add("A%s:%s" % (number, year))
    return ", ".join(sorted(entries))


class SemgrepAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status != "FAILED":
                result.fail("Semgrep payload was empty; findings could not be normalised.")
            return []

        results = payload.get("results")
        if results is None:
            result.fail("Semgrep payload contains no 'results' array; output cannot be trusted.")
            return []

        engine = payload.get("_engine") or TOOL
        findings: List[Finding] = []
        for item in results:
            try:
                findings.append(self._to_finding(item, engine, context))
            except Exception as exc:  # noqa: BLE001 - one bad record must not hide the rest
                result.partial("Skipped a malformed Semgrep record: %s" % exc)
        return findings

    def _to_finding(self, item: Dict[str, Any], engine: str, context: RunContext) -> Finding:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = item.get("check_id") or ""
        path = item.get("path") or ""
        line = (item.get("start") or {}).get("line") or 0
        message = extra.get("message") or rule

        # Prefer the rule's declared impact; fall back to Semgrep's severity.
        raw_severity = metadata.get("impact") or extra.get("severity") or ""
        mapped = SEVERITY_MAP.get(str(raw_severity).upper(), None)
        severity = normalise_severity(mapped or raw_severity)

        confidence = str(metadata.get("confidence") or "").upper()
        evidence_parts = ["%s:%s" % (path or "<unknown file>", line or 0), "rule=%s" % (rule or "<none>")]
        if confidence:
            evidence_parts.append("confidence=%s" % confidence)
        if metadata.get("category"):
            evidence_parts.append("category=%s" % metadata["category"])
        # extra.lines (matched source) intentionally omitted -- see module docstring.

        references = _as_list(metadata.get("references"))[:3]

        # Framework-owned rules carry their own remediation and rationale, written
        # for this report rather than for a rule catalogue. Prefer them: "apply the
        # fix the rule describes" is useless advice when we wrote the rule and can
        # simply say what the fix is.
        framework_rule = bool(rule) and str(rule).startswith(RULE_ID_PREFIX)
        rule_remediation = str(metadata.get("remediation") or "").strip()
        if framework_rule and rule_remediation:
            remediation = rule_remediation
        else:
            remediation = (
                "Review the Semgrep rule %s and apply the fix it describes in application code."
                % (rule or "<unknown>")
            )
        if references:
            remediation += " References: %s" % ", ".join(references)

        # A framework rule declares which normalized category it belongs to, so an
        # information-disclosure rule is filed as information_disclosure rather
        # than swept into the generic SAST bucket.
        declared_category = str(metadata.get("category") or "").strip().lower()
        category = (
            declared_category
            if framework_rule and declared_category in KNOWN_CATEGORIES
            else "sast_finding"
        )

        finding = Finding(
            tool=engine,
            category=category,
            severity=severity,
            raw_severity=str(raw_severity),
            cwe=_extract_cwe(metadata),
            owasp=_extract_owasp(metadata),
            file=path,
            line=line,
            evidence=" | ".join(evidence_parts),
            description=message,
            impact=(
                str(metadata.get("rationale") or "").strip()
                if framework_rule and metadata.get("rationale")
                else (
                    "Semgrep matched a pattern associated with this weakness class. Confidence is "
                    "%s; verify reachability from untrusted input before prioritising."
                    % (confidence or "not stated")
                )
            ),
            remediation=remediation,
            rule=rule,
            native_id=str(extra.get("fingerprint") or ""),
            tags=(
                ([str(metadata.get("category"))] if metadata.get("category") else [])
                # An explicit origin tag. The engine is still Semgrep/OpenGrep --
                # we own the rule, not the matcher -- so the tool field stays
                # accurate while the report can still attribute the rule to the
                # framework's own pack.
                + (["framework-secure-coding"] if framework_rule else [])
            ),
            component=path,
            phase=2,
            scanner_category=CATEGORY_KEY,
        )
        return self.stamp(finding, context)
