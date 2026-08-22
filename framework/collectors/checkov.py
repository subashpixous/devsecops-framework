"""Checkov collector — Infrastructure as Code security.

Runs only when the detector found IaC. Checkov exits 1 when checks fail, which
is a completed scan.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "checkov"
CATEGORY_KEY = "iac_scanning"

# 0 = all checks passed, 1 = failed checks present. Both are completed scans.
ACCEPT_RC = (0, 1)
DEFAULT_TIMEOUT = 1200

SKIP_PATHS = (
    "node_modules", "dist", "build", ".git", ".angular", ".next", "vendor",
    ".venv", "venv", "__pycache__", "bin", "obj", "target",
)


class CheckovCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"workspace", "timeout", "frameworks"}

    def __init__(
        self,
        workspace: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        frameworks: Optional[List[str]] = None,
    ) -> None:
        self.workspace = workspace
        self.timeout = timeout
        self.frameworks = frameworks or []

    def collect(self) -> ScannerResult:
        result = self.new_result()

        if not tool_available(TOOL):
            return result.fail(
                "checkov is not installed or not on PATH. IaC scanning did NOT run, so this "
                "category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(TOOL)

        argv = [TOOL, "--directory", self.workspace, "--output", "json", "--quiet", "--compact"]
        for path in SKIP_PATHS:
            argv += ["--skip-path", path]
        if self.frameworks:
            for framework in self.frameworks:
                argv += ["--framework", framework]
            result.metadata["frameworks"] = self.frameworks

        proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()

        if not accepted(proc, ACCEPT_RC):
            return result.fail("checkov did not complete: %s" % proc.summary()).finish()

        raw = (proc.stdout or "").strip()
        if not raw:
            return result.fail("checkov produced no output; results cannot be trusted.").finish()

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
            failed.extend(results.get("failed_checks") or [])
            summary = block.get("summary") or {}
            passed_count += int(summary.get("passed") or 0)

        result.payload = {
            "_tool": TOOL,
            "failed_checks": failed,
            "passed_count": passed_count,
            "block_count": len(blocks),
        }
        result.metadata["failed_checks"] = len(failed)
        result.metadata["passed_checks"] = passed_count
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> CheckovCollector:
    return CheckovCollector(**{k: v for k, v in kwargs.items() if k in CheckovCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.checkov_adapter import CheckovAdapter

    return CheckovAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Checkov Infrastructure-as-Code misconfiguration scanning.",
    )
)
