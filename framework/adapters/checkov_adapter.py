"""Checkov -> common Finding schema.

Checkov reports three different classes of problem. Each is adapted into the
category that actually owns it, so a finding always carries verdict weight in a
category that applies to the project:

    secrets     CKV_SECRET_*    -> secret_scanning      (category "secret")
    container   CKV_DOCKER_*    -> container_hardening  (category "misconfiguration")
    iac         everything else -> iac_scanning         (category "misconfiguration")
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "checkov"

# Checkov often omits severity in the community edition. Absent severity must not
# become INFO, so it is left to normalise to UNKNOWN, which fails closed.
GUIDELINE_FALLBACK = "Consult the Checkov policy documentation for this check ID."

# Fields the collector nulls out because they can echo matched source. If any of
# them arrives populated, stripping regressed and the adapter refuses the record
# rather than publishing a credential into a downloadable artifact.
SECRET_BEARING_FIELDS = ("code_block", "fixed_definition", "details", "evaluations")

_SECRET_IMPACT = (
    "A credential is present in committed source. Anyone with read access to the "
    "repository can recover it, and removing it from the working tree does not remove "
    "it from git history."
)
_SECRET_REMEDIATION = (
    "1) Rotate the credential at its provider. 2) Remove it from the working tree and "
    "move it to a secret store or injected environment variable. 3) Treat the value as "
    "compromised for as long as it remains in history."
)
_CONTAINER_IMPACT = (
    "The container build definition is insecure, so every image built from it inherits "
    "the weakness. Fixing a running container does not fix the next build."
)
_IAC_IMPACT = (
    "Infrastructure-as-code defines this resource insecurely. The weakness is "
    "provisioned every time this template is applied, so it reappears after any "
    "manual fix."
)


class CheckovAdapter(Adapter):
    """Adapts one Checkov concern into its owning category."""

    tool = TOOL
    category_key = "iac_scanning"
    concern = "iac"

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
            leaked = [f for f in SECRET_BEARING_FIELDS if check.get(f)]
            if leaked:
                result.fail(
                    "Checkov record still carries potentially secret-bearing field(s) %s; "
                    "refusing to normalise it." % ", ".join(sorted(leaked))
                )
                return []
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

        is_secret = str(check_id).startswith("CKV_SECRET")

        evidence = ["%s:%s" % (path or "<unknown>", line or 0), "check=%s" % (check_id or "<none>")]
        if resource and not is_secret:
            evidence.append("resource=%s" % resource)
        elif resource:
            # For a secret check, `resource` is Checkov's hash of the matched value.
            # It is a correlation handle, not a location, so it is labelled as such.
            evidence.append("match_id=%s" % resource)
        if check.get("check_class"):
            evidence.append("class=%s" % check["check_class"])
        if check.get("_redacted_fields"):
            evidence.append("redacted=%s" % ",".join(check["_redacted_fields"]))

        if is_secret:
            finding_category, cwe, owasp = "secret", "CWE-798", "A7:2021"
            impact, fallback = _SECRET_IMPACT, _SECRET_REMEDIATION
        elif self.concern == "container":
            finding_category, cwe, owasp = "misconfiguration", "CWE-250", "A5:2021"
            impact, fallback = _CONTAINER_IMPACT, GUIDELINE_FALLBACK
        else:
            finding_category, cwe, owasp = "misconfiguration", "", "A5:2021"
            impact, fallback = _IAC_IMPACT, GUIDELINE_FALLBACK

        return self.stamp(
            Finding(
                tool=TOOL,
                category=finding_category,
                severity=normalise_severity(severity),
                raw_severity=str(severity or ""),
                cwe=cwe,
                owasp=owasp,
                file=path,
                line=line,
                evidence=" | ".join(evidence),
                description=("%s: %s" % (check_id, name)).strip(": "),
                impact=impact,
                remediation=guideline or fallback,
                rule=check_id,
                native_id=str(check_id or ""),
                # A secret's component is the file that carries it. Using Checkov's
                # value-hash there would make every finding look like a distinct
                # component and hide which files are affected.
                component=(path if is_secret else (resource or path)),
                phase=2,
                scanner_category=self.category_key,
            ),
            context,
        )


class CheckovIacAdapter(CheckovAdapter):
    category_key = "iac_scanning"
    concern = "iac"


class CheckovSecretsAdapter(CheckovAdapter):
    category_key = "secret_scanning"
    concern = "secrets"


class CheckovDockerfileAdapter(CheckovAdapter):
    category_key = "container_hardening"
    concern = "container"


_BY_CONCERN = {
    "iac": CheckovIacAdapter,
    "secrets": CheckovSecretsAdapter,
    "container": CheckovDockerfileAdapter,
}


def build_adapter(concern: str) -> CheckovAdapter:
    return _BY_CONCERN[concern]()
