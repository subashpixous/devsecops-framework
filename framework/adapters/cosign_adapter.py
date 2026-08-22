"""cosign -> common Finding schema.

An image that is not signed produces a finding. A signature that could not be
checked produces nothing here -- the collector has already degraded the result,
so the category resolves to NOT_VERIFIED rather than reporting a false "unsigned".
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding
from .base import Adapter

TOOL = "cosign"
CATEGORY_KEY = "artifact_signing"


class CosignAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("cosign payload was empty; findings could not be normalised.")
            return []

        verifications = payload.get("verifications")
        if verifications is None:
            result.fail("cosign payload contains no 'verifications' array; output cannot be trusted.")
            return []

        findings: List[Finding] = []
        for entry in verifications:
            if entry.get("verified") or entry.get("inconclusive"):
                continue
            image = entry.get("image", "")
            findings.append(
                self.stamp(
                    Finding(
                        tool=TOOL,
                        category="supply_chain",
                        severity="MEDIUM",
                        cwe="CWE-494",
                        owasp="A8:2021",
                        file="",
                        line=0,
                        component=image,
                        evidence="image=%s | mode=%s | verification failed"
                                 % (image, entry.get("mode", "")),
                        description="Container image has no valid signature: %s" % image,
                        impact=(
                            "Without a verifiable signature there is no cryptographic proof that "
                            "the deployed image is the one this pipeline built. A substituted or "
                            "tampered image would not be detected."
                        ),
                        remediation=(
                            "Sign the image at release time with cosign and verify the signature "
                            "before deployment. Combine with immutable digest-based tags so the "
                            "verified artifact is the one that actually runs."
                        ),
                        rule="cosign.unsigned_artifact",
                        native_id=image,
                        phase=3,
                        scanner_category=CATEGORY_KEY,
                    ),
                    context,
                )
            )
        return findings
