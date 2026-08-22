"""Prowler collector — cloud security posture assessment.

Credential-gated. Prowler needs cloud credentials; without them the category
reports NOT_VERIFIED with the exact missing input rather than passing.

Read-only: Prowler performs describe/list assessment calls only. No cloud
resource is created, modified or deleted by this collector.
"""

from __future__ import annotations

import glob
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "prowler"
CATEGORY_KEY = "cloud_posture"

# 3 = findings present. 0 = clean. Both are completed assessments.
ACCEPT_RC = (0, 3)
DEFAULT_TIMEOUT = 3600

PROVIDER_CREDENTIAL_HINT = {
    "aws": "AWS credentials (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, an assumed role, or OIDC)",
    "azure": "Azure credentials (AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID)",
    "gcp": "GCP credentials (GOOGLE_APPLICATION_CREDENTIALS)",
}


def _aws_credentials_present() -> bool:
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return True
    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or os.environ.get("AWS_ROLE_ARN"):
        return True
    if os.environ.get("AWS_PROFILE"):
        return True
    return os.path.exists(os.path.expanduser("~/.aws/credentials"))


def credentials_present(provider: str) -> bool:
    if provider == "aws":
        return _aws_credentials_present()
    if provider == "azure":
        return all(os.environ.get(k) for k in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"))
    if provider == "gcp":
        return bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
    return False


class ProwlerCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"cloud", "timeout", "prowler_checks"}

    def __init__(self, cloud: str = "", timeout: int = DEFAULT_TIMEOUT, prowler_checks: str = "") -> None:
        self.provider = (cloud or "").strip().lower()
        self.timeout = timeout
        self.prowler_checks = prowler_checks

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["provider"] = self.provider or "NOT_ESTABLISHED"
        result.metadata["read_only"] = True

        if not self.provider:
            return result.skip(
                "No cloud provider was established for this project. Cloud posture assessment did "
                "NOT run, so this category is unverified."
            ).finish()

        if self.provider not in PROVIDER_CREDENTIAL_HINT:
            return result.skip(
                "Cloud provider %r is not supported by this collector. Cloud posture assessment "
                "did NOT run, so this category is unverified." % self.provider
            ).finish()

        if not tool_available(TOOL):
            return result.fail(
                "prowler is not installed or not on PATH. Cloud posture assessment did NOT run, "
                "so this category is unverified."
            ).finish()

        if not credentials_present(self.provider):
            return result.skip(
                "No %s credentials are available to this run. Cloud posture assessment did NOT "
                "run, so this category is unverified. Required input: %s, granted read-only "
                "assessment permissions (for AWS, the SecurityAudit and ViewOnlyAccess policies)."
                % (self.provider.upper(), PROVIDER_CREDENTIAL_HINT[self.provider])
            ).finish()

        result.metadata["version"] = tool_version(TOOL, ("--version",))
        outdir = tempfile.mkdtemp(prefix="prowler-")

        argv = [
            TOOL, self.provider,
            "--output-formats", "json-ocsf",
            "--output-directory", outdir,
            "--output-filename", "prowler",
            "--no-banner",
            "--ignore-exit-code-3",
        ]
        if self.prowler_checks:
            argv += ["--checks", *self.prowler_checks.split(",")]

        proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()

        matches = glob.glob(os.path.join(outdir, "*.ocsf.json")) + glob.glob(os.path.join(outdir, "*.json"))
        if not accepted(proc, ACCEPT_RC) and not matches:
            return result.fail("prowler did not complete: %s" % proc.summary()).finish()
        if not matches:
            return result.fail("prowler produced no output file; results cannot be trusted.").finish()

        records: List[Dict[str, Any]] = []
        for path in matches:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                records.extend(data if isinstance(data, list) else [data])
            except (OSError, ValueError) as exc:
                result.partial("Prowler output %s could not be parsed: %s" % (os.path.basename(path), exc))

        if not records:
            return result.fail("Prowler output contained no parsable findings.").finish()

        result.payload = {"_tool": TOOL, "_provider": self.provider, "findings": records}
        result.metadata["record_count"] = len(records)
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> ProwlerCollector:
    return ProwlerCollector(**{k: v for k, v in kwargs.items() if k in ProwlerCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.prowler_adapter import ProwlerAdapter

    return ProwlerAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Prowler cloud security posture assessment (read-only; requires cloud credentials).",
    )
)
