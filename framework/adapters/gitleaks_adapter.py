"""Gitleaks -> common Finding schema.

The collector has already stripped `Secret` and `Match`. This adapter asserts
that stripping happened rather than trusting it, because a regression here would
publish credentials into a downloadable artifact.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "gitleaks"
CATEGORY_KEY = "secret_scanning"

FORBIDDEN_FIELDS = ("Secret", "Match", "secret", "match")


class GitleaksAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status != "FAILED":
                result.fail("Gitleaks payload was empty; findings could not be normalised.")
            return []

        records = payload.get("findings")
        if records is None:
            result.fail("Gitleaks payload contains no 'findings' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for record in records:
            # Defence in depth: refuse to normalise a record still carrying a secret.
            leaked = [f for f in FORBIDDEN_FIELDS if f in record]
            if leaked:
                result.fail(
                    "Gitleaks record still contains raw secret field(s) %s; refusing to normalise. "
                    "This is a framework defect, not a scan result." % ", ".join(leaked)
                )
                return []
            try:
                findings.append(self._to_finding(record, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed Gitleaks record: %s" % exc)
        return findings

    def _to_finding(self, record: Dict[str, Any], context: RunContext) -> Finding:
        rule = record.get("RuleID") or record.get("ruleID") or ""
        path = record.get("File") or record.get("file") or ""
        line = record.get("StartLine") or record.get("startLine") or 0
        description = record.get("Description") or record.get("description") or "Committed secret detected"
        commit = record.get("Commit") or ""
        author = record.get("Author") or ""
        entropy = record.get("Entropy")
        secret_length = record.get("SecretLength")

        evidence_parts = ["%s:%s" % (path or "<unknown file>", line or 0), "rule=%s" % (rule or "<none>")]
        if commit:
            evidence_parts.append("commit=%s" % str(commit)[:12])
        if author:
            evidence_parts.append("author=%s" % author)
        if entropy is not None:
            try:
                evidence_parts.append("entropy=%.2f" % float(entropy))
            except (TypeError, ValueError):
                pass
        if secret_length:
            evidence_parts.append("secret_length=%s" % secret_length)
        evidence_parts.append("secret_value=WITHHELD")

        in_history = bool(commit)
        finding = Finding(
            tool=TOOL,
            category="secret",
            # A committed credential is always treated as critical. Gitleaks does
            # not grade severity, and under-grading a live secret is unsafe.
            severity="CRITICAL",
            raw_severity="",
            cwe="CWE-798",
            owasp="A7:2021",
            file=path,
            line=line,
            evidence=" | ".join(evidence_parts),
            description=description,
            impact=(
                "A credential is present in %s. Anyone with read access to the repository holds it. "
                "Removing it from the current tree does NOT invalidate it -- the credential must be "
                "rotated at its source."
                % ("committed git history" if in_history else "the working tree")
            ),
            remediation=(
                "1) Rotate the credential at its provider. 2) Remove it from the working tree and "
                "move it to a secret store. 3) Purge it from git history. Rotation comes first: "
                "history rewriting does not invalidate a credential that has already been copied."
            ),
            first_seen=str(record.get("Date") or ""),
            rule=rule,
            native_id=str(record.get("Fingerprint") or ""),
            tags=[str(t) for t in (record.get("Tags") or [])],
            component=path,
            phase=2,
            scanner_category=CATEGORY_KEY,
        )
        return self.stamp(finding, context)
