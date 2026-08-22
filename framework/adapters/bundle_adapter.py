"""Frontend bundle scanner -> common Finding schema.

Shared by the build-time bundle scanner and the live JavaScript bundle
validator, so a secret is described identically whether it was found in a built
artifact or in one served from production.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "bundle-scanner"
CATEGORY_KEY = "frontend_bundle_secrets"

PHASE_BY_CATEGORY = {"frontend_bundle_secrets": 3, "runtime_probes": 5}


class BundleAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Bundle scanner payload was empty; findings could not be normalised.")
            return []

        matches = payload.get("matches")
        if matches is None:
            result.fail("Bundle scanner payload contains no 'matches' array; output cannot be trusted.")
            return []

        category_key = result.category_key or CATEGORY_KEY
        findings: List[Finding] = []

        for match in matches:
            try:
                findings.append(self._match_to_finding(match, category_key, context))
            except Exception as exc:  # noqa: BLE001
                result.partial("Skipped a malformed bundle match: %s" % exc)

        # Source maps shipped to production disclose original source.
        for sourcemap in payload.get("sourcemaps") or []:
            findings.append(self._sourcemap_to_finding(sourcemap, category_key, context))

        return findings

    def _match_to_finding(self, match: Dict[str, Any], category_key: str, context: RunContext) -> Finding:
        origin = "served from production" if category_key == "runtime_probes" else "in the built bundle"
        evidence = [
            "%s:%s" % (match.get("file") or "<unknown>", match.get("line") or 0),
            "detector=%s" % match.get("detector"),
            match.get("reference", ""),           # length + hash, never the value
            "entropy=%s" % match.get("entropy"),
            "value=WITHHELD",
        ]
        return self.stamp(
            Finding(
                tool=TOOL,
                category="secret" if "key" in str(match.get("detector")) or "secret" in str(match.get("detector")) else "information_disclosure",
                severity=normalise_severity(match.get("severity")),
                raw_severity=str(match.get("severity") or ""),
                cwe=str(match.get("cwe") or ""),
                owasp="A7:2021" if str(match.get("cwe")) == "CWE-798" else "A5:2021",
                file=str(match.get("file") or ""),
                line=int(match.get("line") or 0),
                evidence=" | ".join(p for p in evidence if p),
                description="%s (%s)" % (match.get("description") or "Bundle exposure", origin),
                impact=(
                    "This value is delivered to every visitor's browser. Client-side code is public; "
                    "anything embedded in it must be treated as disclosed."
                ),
                remediation=str(match.get("remediation") or ""),
                rule=str(match.get("detector") or ""),
                component=str(match.get("file") or ""),
                phase=PHASE_BY_CATEGORY.get(category_key, 3),
                scanner_category=category_key,
            ),
            context,
        )

    def _sourcemap_to_finding(self, path: str, category_key: str, context: RunContext) -> Finding:
        return self.stamp(
            Finding(
                tool=TOOL,
                category="information_disclosure",
                severity="LOW",
                cwe="CWE-540",
                owasp="A5:2021",
                file=path,
                line=0,
                evidence="%s | sourcemap shipped alongside production bundle" % path,
                description="Source map present in production build output",
                impact=(
                    "Source maps reconstruct original source, including comments and internal "
                    "structure, from the minified bundle. They materially assist an attacker "
                    "reading client-side logic."
                ),
                remediation=(
                    "Disable source-map emission for production builds, or ensure maps are not "
                    "deployed to the public web root."
                ),
                rule="sourcemap_in_production",
                component=path,
                phase=PHASE_BY_CATEGORY.get(category_key, 3),
                scanner_category=category_key,
            ),
            context,
        )
