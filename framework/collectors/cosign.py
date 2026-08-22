"""cosign / Sigstore collector — artifact signature and provenance verification.

This collector VERIFIES signatures; it never signs. Signing is a release action
that requires a private key, and a security-validation pipeline must not hold
one. An unsigned image is reported as a finding, not silently accepted.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "cosign"
CATEGORY_KEY = "artifact_signing"

ACCEPT_RC = (0, 1)  # 1 = verification failed, which is a result, not a crash
DEFAULT_TIMEOUT = 600

KEY_ENV = "COSIGN_PUBLIC_KEY"
IDENTITY_ENV = "COSIGN_CERTIFICATE_IDENTITY"
ISSUER_ENV = "COSIGN_CERTIFICATE_OIDC_ISSUER"


class CosignCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"images", "timeout"}

    def __init__(self, images: Optional[List[str]] = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.images = [i for i in (images or []) if i]
        self.timeout = timeout

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["verifies_only"] = True

        if not self.images:
            return result.skip(
                "No container image reference was supplied (input 'images'). Artifact signature "
                "verification did NOT run, so this category is unverified."
            ).finish()

        if not tool_available(TOOL):
            return result.fail(
                "cosign is not installed or not on PATH. Signature verification did NOT run, so "
                "this category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(TOOL, ("version",))

        public_key = os.environ.get(KEY_ENV, "")
        identity = os.environ.get(IDENTITY_ENV, "")
        issuer = os.environ.get(ISSUER_ENV, "")

        if not public_key and not (identity and issuer):
            return result.skip(
                "No verification material configured. Set %s for key-based verification, or both "
                "%s and %s for keyless (Fulcio) verification. Signature verification did NOT run, "
                "so this category is unverified." % (KEY_ENV, IDENTITY_ENV, ISSUER_ENV)
            ).finish()

        mode = "key" if public_key else "keyless"
        result.metadata["mode"] = mode

        verifications: List[Dict[str, Any]] = []
        for image in self.images:
            argv = [TOOL, "verify", "--output", "json"]
            if public_key:
                argv += ["--key", public_key]
            else:
                argv += ["--certificate-identity", identity, "--certificate-oidc-issuer", issuer]
            argv.append(image)

            proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
            verified = accepted(proc, (0,))
            entry: Dict[str, Any] = {
                "image": image,
                "verified": verified,
                "mode": mode,
                "returncode": proc.returncode,
                "detail": (proc.stderr or "").strip()[-500:] if not verified else "",
            }
            if verified:
                try:
                    entry["signatures"] = json.loads(proc.stdout or "[]")
                except ValueError:
                    entry["signatures"] = []
                    entry["detail"] = "cosign reported success but its JSON output was unparsable."
            elif not proc.available or proc.timed_out or proc.error:
                # Distinguish "not signed" from "we could not tell".
                entry["inconclusive"] = True
                entry["detail"] = proc.summary()
            verifications.append(entry)

        inconclusive = [v for v in verifications if v.get("inconclusive")]
        if inconclusive and len(inconclusive) == len(verifications):
            return result.fail(
                "cosign could not complete verification for any image: %s"
                % "; ".join(v["detail"] for v in inconclusive)
            ).finish()
        if inconclusive:
            result.partial("Verification was inconclusive for %d image(s)." % len(inconclusive))

        result.payload = {"_tool": TOOL, "_mode": mode, "verifications": verifications}
        result.metadata["verified_count"] = sum(1 for v in verifications if v["verified"])
        result.metadata["image_count"] = len(verifications)
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> CosignCollector:
    return CosignCollector(**{k: v for k, v in kwargs.items() if k in CosignCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.cosign_adapter import CosignAdapter

    return CosignAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="cosign/Sigstore artifact signature verification (verify-only; never signs).",
    )
)
