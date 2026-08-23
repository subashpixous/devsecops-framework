"""Checkov collector.

Checkov covers three distinct security concerns that belong to three distinct
categories. Running it once and filing every result under "Infrastructure as
Code" mis-classifies two of them, and on a project with no IaC that category is
NOT_APPLICABLE -- so container and secret findings would be reported but would
carry no verdict weight.

Each concern therefore gets its own framework-scoped scan and its own category:

    checkov-iac         --framework <iac frameworks>   -> iac_scanning
    checkov-secrets     --framework secrets            -> secret_scanning
    checkov-dockerfile  --framework dockerfile         -> container_hardening

Checkov exits 1 when checks fail, which is a completed scan.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "checkov"

CATEGORY_IAC = "iac_scanning"
CATEGORY_SECRETS = "secret_scanning"
CATEGORY_CONTAINER = "container_hardening"

# 0 = all checks passed, 1 = failed checks present. Both are completed scans.
ACCEPT_RC = (0, 1)
DEFAULT_TIMEOUT = 1200

# Infrastructure-as-code frameworks only. `secrets` and `dockerfile` are scanned
# by their own registrations so their findings reach their own categories.
IAC_FRAMEWORKS = (
    "terraform", "terraform_plan", "cloudformation", "serverless",
    "arm", "bicep", "kustomize", "helm", "kubernetes", "ansible",
    "github_actions", "gitlab_ci", "circleci_pipelines", "azure_pipelines",
)

SKIP_PATHS = (
    "node_modules", "dist", "build", ".git", ".angular", ".next", "vendor",
    ".venv", "venv", "__pycache__", "bin", "obj", "target",
)

# Checkov's secret checks can echo matched source. None of these fields is needed
# to locate or act on a finding, and any of them may carry credential material, so
# they are dropped before the payload is attached to the result -- the same
# stripping contract Gitleaks collection follows.
SECRET_BEARING_FIELDS = ("code_block", "fixed_definition", "details", "evaluations")


def _strip_secret_material(check: Dict[str, Any]) -> Dict[str, Any]:
    """Remove any field that could carry a matched secret value."""
    cleaned = dict(check)
    redacted = []
    for field in SECRET_BEARING_FIELDS:
        if cleaned.get(field):
            redacted.append(field)
        cleaned[field] = None
    if redacted:
        cleaned["_redacted_fields"] = redacted
    return cleaned


class _CheckovBase(Collector):
    """One framework-scoped Checkov scan."""

    tool = TOOL
    category_key = CATEGORY_IAC
    frameworks: tuple = ()
    concern = "iac"
    ACCEPTS = {"workspace", "timeout"}

    def __init__(self, workspace: str = ".", timeout: int = DEFAULT_TIMEOUT) -> None:
        self.workspace = workspace
        self.timeout = timeout

    def collect(self) -> ScannerResult:
        result = self.new_result()

        if not tool_available(TOOL):
            return result.fail(
                "checkov is not installed or not on PATH. The %s scan did NOT run, so this "
                "category is unverified." % self.concern
            ).finish()

        result.metadata["version"] = tool_version(TOOL)
        result.metadata["concern"] = self.concern
        result.metadata["frameworks"] = list(self.frameworks)

        argv = [TOOL, "--directory", self.workspace, "--output", "json", "--quiet", "--compact"]
        for path in SKIP_PATHS:
            argv += ["--skip-path", path]
        for framework in self.frameworks:
            argv += ["--framework", framework]

        proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()

        if not accepted(proc, ACCEPT_RC):
            return result.fail("checkov did not complete: %s" % proc.summary()).finish()

        raw = (proc.stdout or "").strip()
        if not raw:
            # A framework-scoped run prints nothing when the project contains no
            # files of that kind. That is an empty scan, not an untrustworthy one.
            result.payload = {
                "_tool": TOOL,
                "_concern": self.concern,
                "failed_checks": [],
                "passed_count": 0,
                "block_count": 0,
            }
            result.metadata["failed_checks"] = 0
            result.metadata["passed_checks"] = 0
            return result.succeed().finish()

        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            return result.fail("checkov output is not valid JSON: %s" % exc).finish()

        # Checkov emits either one object or a list of per-framework objects.
        blocks: List[Dict[str, Any]] = parsed if isinstance(parsed, list) else [parsed]

        failed: List[Dict[str, Any]] = []
        passed_count = 0
        for block in blocks:
            if not isinstance(block, dict):
                continue
            results = block.get("results") or {}
            for check in results.get("failed_checks") or []:
                failed.append(_strip_secret_material(check))
            summary = block.get("summary") or {}
            passed_count += int(summary.get("passed") or 0)

        result.payload = {
            "_tool": TOOL,
            "_concern": self.concern,
            "failed_checks": failed,
            "passed_count": passed_count,
            "block_count": len(blocks),
        }
        result.metadata["failed_checks"] = len(failed)
        result.metadata["passed_checks"] = passed_count
        return result.succeed().finish()


class CheckovIacCollector(_CheckovBase):
    category_key = CATEGORY_IAC
    frameworks = IAC_FRAMEWORKS
    concern = "iac"


class CheckovSecretsCollector(_CheckovBase):
    category_key = CATEGORY_SECRETS
    frameworks = ("secrets",)
    concern = "secrets"


class CheckovDockerfileCollector(_CheckovBase):
    category_key = CATEGORY_CONTAINER
    frameworks = ("dockerfile",)
    concern = "container"


# Backwards compatibility: the original single-scan collector name.
CheckovCollector = CheckovIacCollector


def _collector_factory(cls: Any) -> Any:
    def build(**kwargs: Any) -> Any:
        return cls(**{k: v for k, v in kwargs.items() if k in cls.ACCEPTS})

    return build


def _adapter_factory(concern: str) -> Any:
    def build(**_: Any) -> Any:
        from ..adapters.checkov_adapter import build_adapter

        return build_adapter(concern)

    return build


for _tool_name, _cls, _concern, _desc in (
    ("checkov-iac", CheckovIacCollector, "iac",
     "Checkov Infrastructure-as-Code misconfiguration scanning."),
    ("checkov-secrets", CheckovSecretsCollector, "secrets",
     "Checkov committed-secret detection (values stripped at collection)."),
    ("checkov-dockerfile", CheckovDockerfileCollector, "container",
     "Checkov container build-definition hardening checks."),
):
    register_scanner(
        ScannerRegistration(
            tool=_tool_name,
            category_key=_cls.category_key,
            collector_factory=_collector_factory(_cls),
            adapter_factory=_adapter_factory(_concern),
            description=_desc,
        )
    )
