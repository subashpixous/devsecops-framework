"""Trivy -> common Finding schema.

One adapter serves all four Trivy modes. The scanner_category is taken from the
ScannerResult, so the same code normalises dependency CVEs, image CVEs and
Kubernetes misconfiguration without branching on project type.

The SBOM mode produces no findings by design: it emits an artifact, and its
category passes or fails on whether that artifact was generated.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "trivy"

_CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# Which finding class each category produces.
CATEGORY_FINDING_CLASS = {
    "sca_dependencies": "dependency_vulnerability",
    "container_image": "container_vulnerability",
    "kubernetes_security": "misconfiguration",
    "sbom": "sbom",
}

PHASE_BY_CATEGORY = {
    "sca_dependencies": 2,
    "container_image": 3,
    "sbom": 3,
    "kubernetes_security": 3,
}


class TrivyAdapter(Adapter):
    tool = TOOL
    category_key = ""  # set per result

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Trivy payload was empty; findings could not be normalised.")
            return []

        category_key = result.category_key
        sections = payload.get("Results")
        if sections is None:
            result.fail("Trivy payload contains no 'Results' array; output cannot be trusted.")
            return []

        # SBOM mode is an artifact producer, not a finding producer.
        if category_key == "sbom":
            return []

        findings: List[Finding] = []
        for section in sections:
            if not isinstance(section, dict):
                continue
            target = section.get("Target") or ""
            image = section.get("_image") or ""
            pkg_type = section.get("Type") or ""

            for vuln in section.get("Vulnerabilities") or []:
                try:
                    findings.append(self._vuln_to_finding(vuln, target, image, pkg_type, category_key, context))
                except Exception as exc:  # noqa: BLE001
                    result.partial("Skipped a malformed Trivy vulnerability record: %s" % exc)

            for misconf in section.get("Misconfigurations") or []:
                try:
                    findings.append(self._misconf_to_finding(misconf, target, category_key, context))
                except Exception as exc:  # noqa: BLE001
                    result.partial("Skipped a malformed Trivy misconfiguration record: %s" % exc)

        return findings

    def _vuln_to_finding(
        self, vuln: Dict[str, Any], target: str, image: str, pkg_type: str,
        category_key: str, context: RunContext,
    ) -> Finding:
        vuln_id = vuln.get("VulnerabilityID") or ""
        pkg = vuln.get("PkgName") or ""
        installed = vuln.get("InstalledVersion") or ""
        fixed = vuln.get("FixedVersion") or ""
        title = vuln.get("Title") or vuln.get("Description") or vuln_id
        pkg_path = vuln.get("PkgPath") or target

        cwes = sorted({m.group(0).upper() for c in (vuln.get("CweIDs") or []) for m in [_CWE_PATTERN.search(str(c))] if m})

        evidence = [
            "package=%s@%s" % (pkg or "<unknown>", installed or "?"),
            "id=%s" % (vuln_id or "<none>"),
        ]
        if pkg_type:
            evidence.append("ecosystem=%s" % pkg_type)
        if image:
            evidence.append("image=%s" % image)
        if target and target != pkg_path:
            evidence.append("target=%s" % target)
        evidence.append("fixed_version=%s" % (fixed or "none available"))

        if fixed:
            remediation = "Upgrade %s from %s to %s or later." % (pkg, installed or "current", fixed)
        else:
            remediation = (
                "No fixed version is published for %s %s. Assess exploitability in context, and "
                "consider replacing the dependency, pinning a patched fork, or applying a "
                "compensating control." % (pkg, installed or "")
            )

        return self.stamp(
            Finding(
                tool=TOOL,
                category=CATEGORY_FINDING_CLASS.get(category_key, "dependency_vulnerability"),
                severity=normalise_severity(vuln.get("Severity")),
                raw_severity=str(vuln.get("Severity") or ""),
                cwe=", ".join(cwes),
                owasp="A6:2021",  # Vulnerable and Outdated Components
                file=pkg_path,
                line=0,
                evidence=" | ".join(evidence),
                description=("%s: %s" % (vuln_id, title)).strip(": "),
                impact=(
                    "A known vulnerability is present in a shipped dependency. Exploitability "
                    "depends on whether the affected code path is reachable in this application."
                ),
                remediation=remediation,
                rule=vuln_id,
                native_id=vuln_id,
                component="%s@%s" % (pkg, installed) if pkg else pkg_path,
                tags=[pkg_type] if pkg_type else [],
                phase=PHASE_BY_CATEGORY.get(category_key, 2),
                scanner_category=category_key,
            ),
            context,
        )

    def _misconf_to_finding(
        self, misconf: Dict[str, Any], target: str, category_key: str, context: RunContext
    ) -> Finding:
        check_id = misconf.get("ID") or misconf.get("AVDID") or ""
        cause = misconf.get("CauseMetadata") or {}
        line = cause.get("StartLine") or 0
        resource = cause.get("Resource") or ""

        evidence = ["%s:%s" % (target or "<unknown>", line or 0), "check=%s" % (check_id or "<none>")]
        if resource:
            evidence.append("resource=%s" % resource)
        if misconf.get("Status"):
            evidence.append("status=%s" % misconf["Status"])

        return self.stamp(
            Finding(
                tool=TOOL,
                category="misconfiguration",
                severity=normalise_severity(misconf.get("Severity")),
                raw_severity=str(misconf.get("Severity") or ""),
                cwe="",
                owasp="A5:2021",  # Security Misconfiguration
                file=target,
                line=line,
                evidence=" | ".join(evidence),
                description=("%s: %s" % (check_id, misconf.get("Title") or misconf.get("Message") or "")).strip(": "),
                impact=misconf.get("Description") or "Insecure configuration detected in a workload or infrastructure definition.",
                remediation=misconf.get("Resolution") or "Apply the remediation described by check %s." % check_id,
                rule=check_id,
                native_id=str(misconf.get("AVDID") or check_id),
                component=resource or target,
                phase=PHASE_BY_CATEGORY.get(category_key, 3),
                scanner_category=category_key,
            ),
            context,
        )
