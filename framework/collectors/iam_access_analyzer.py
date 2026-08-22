"""AWS IAM Access Analyzer collector — externally reachable grants.

Credential-gated and read-only: uses `list-analyzers` and `list-findings` only.
No analyzer is created, no policy is modified.

If no analyzer exists in the account/region, that is itself reported: without an
analyzer AWS is not evaluating external access at all, so the control is absent
rather than passing.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available
from .base import Collector, ScannerResult
from .prowler import credentials_present

TOOL = "aws-iam-access-analyzer"
CATEGORY_KEY = "iam_access_analyzer"

ACCEPT_RC = (0,)
DEFAULT_TIMEOUT = 600
AWS_CLI = "aws"


class IamAccessAnalyzerCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"cloud", "timeout", "aws_region"}

    def __init__(self, cloud: str = "", timeout: int = DEFAULT_TIMEOUT, aws_region: str = "") -> None:
        self.provider = (cloud or "").strip().lower()
        self.timeout = timeout
        self.region = aws_region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""

    def _aws(self, result: ScannerResult, args: List[str]) -> Optional[Dict[str, Any]]:
        argv = [AWS_CLI, "accessanalyzer", *args, "--output", "json"]
        if self.region:
            argv += ["--region", self.region]
        proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
        if not accepted(proc, ACCEPT_RC):
            result.fail("AWS CLI call failed (%s): %s" % (" ".join(args[:1]), proc.summary())).finish()
            return None
        try:
            return json.loads(proc.stdout or "{}")
        except ValueError as exc:
            result.fail("AWS CLI returned output that is not valid JSON: %s" % exc).finish()
            return None

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["read_only"] = True
        result.metadata["region"] = self.region or "NOT_ESTABLISHED"

        if self.provider != "aws":
            return result.skip(
                "Project cloud provider is %r, not AWS. IAM Access Analyzer did NOT run, so this "
                "category is unverified." % (self.provider or "NOT_ESTABLISHED")
            ).finish()

        if not tool_available(AWS_CLI):
            return result.fail(
                "The AWS CLI is not installed or not on PATH. IAM Access Analyzer did NOT run, so "
                "this category is unverified."
            ).finish()

        if not credentials_present("aws"):
            return result.skip(
                "No AWS credentials are available to this run. IAM Access Analyzer did NOT run, so "
                "this category is unverified. Required input: AWS credentials with "
                "access-analyzer:ListAnalyzers and access-analyzer:ListFindings permissions."
            ).finish()

        if not self.region:
            return result.skip(
                "No AWS region was established. IAM Access Analyzer is region-scoped and did NOT "
                "run, so this category is unverified. Required input: AWS_REGION."
            ).finish()

        analyzers = self._aws(result, ["list-analyzers"])
        if analyzers is None:
            return result

        active = [a for a in (analyzers.get("analyzers") or []) if a.get("status") == "ACTIVE"]
        result.metadata["analyzer_count"] = len(active)

        if not active:
            # Absence of an analyzer is a finding in itself, not a pass.
            result.payload = {
                "_tool": TOOL,
                "_region": self.region,
                "analyzers": [],
                "findings": [],
                "no_analyzer_configured": True,
            }
            result.partial(
                "No ACTIVE IAM Access Analyzer exists in region %s. AWS is therefore not "
                "evaluating external access for this account/region." % self.region
            )
            return result.succeed().finish()

        findings: List[Dict[str, Any]] = []
        for analyzer in active:
            arn = analyzer.get("arn")
            if not arn:
                continue
            page = self._aws(result, ["list-findings", "--analyzer-arn", arn, "--max-results", "100"])
            if page is None:
                return result
            for item in page.get("findings") or []:
                item["_analyzer"] = analyzer.get("name", "")
                findings.append(item)

        result.payload = {
            "_tool": TOOL,
            "_region": self.region,
            "analyzers": [{"name": a.get("name"), "type": a.get("type")} for a in active],
            "findings": findings,
            "no_analyzer_configured": False,
        }
        result.metadata["finding_count"] = len(findings)
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> IamAccessAnalyzerCollector:
    return IamAccessAnalyzerCollector(
        **{k: v for k, v in kwargs.items() if k in IamAccessAnalyzerCollector.ACCEPTS}
    )


def _build_adapter(**_: Any) -> Any:
    from ..adapters.iam_adapter import IamAccessAnalyzerAdapter

    return IamAccessAnalyzerAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="AWS IAM Access Analyzer external-access findings (read-only; requires AWS credentials).",
    )
)
