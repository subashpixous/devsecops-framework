"""Semgrep / OpenGrep collector — pattern-based SAST.

Runs the scanner over the workspace and captures its JSON report. Semgrep exits
1 when it finds something, which is a successful scan, not a failure.

OpenGrep is a drop-in fork; if `semgrep` is absent the collector falls back to
`opengrep` and records which engine actually ran.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "semgrep"
CATEGORY_KEY = "sast_semgrep"

# 0 = clean, 1 = findings present. Both mean the scan completed.
ACCEPT_RC = (0, 1)

DEFAULT_CONFIG = "p/default"
DEFAULT_TIMEOUT = 1800

EXCLUDES = (
    "node_modules", "dist", "build", "out", "bin", "obj", ".angular", ".next",
    "vendor", ".venv", "venv", "__pycache__", "coverage", "target", ".git",
)


class SemgrepCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY

    def __init__(
        self,
        workspace: str = ".",
        config: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        binary: Optional[str] = None,
    ) -> None:
        self.workspace = workspace
        # SEMGREP_RULES lets a project pin its own ruleset without code changes.
        self.config = config or os.environ.get("SEMGREP_RULES") or DEFAULT_CONFIG
        self.timeout = timeout
        self.binary = binary or (TOOL if tool_available(TOOL) else "opengrep")

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["engine"] = self.binary
        result.metadata["config"] = self.config

        if not tool_available(self.binary):
            return result.fail(
                "Neither 'semgrep' nor 'opengrep' is installed or on PATH. "
                "Static analysis by this engine did NOT run, so this category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(self.binary)

        argv = [
            self.binary, "scan",
            "--config", self.config,
            "--json",
            "--quiet",
            "--metrics", "off",
            "--timeout", "60",
            "--max-target-bytes", "2000000",
        ]
        for pattern in EXCLUDES:
            argv += ["--exclude", pattern]
        argv.append(self.workspace)

        proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()

        if not accepted(proc, ACCEPT_RC):
            return result.fail("Semgrep did not complete: %s" % proc.summary()).finish()

        try:
            payload = json.loads(proc.stdout or "{}")
        except ValueError as exc:
            return result.fail("Semgrep produced output that is not valid JSON: %s" % exc).finish()

        if not isinstance(payload, dict) or "results" not in payload:
            return result.fail("Semgrep JSON has no 'results' array; output cannot be trusted.").finish()

        errors: List[Any] = payload.get("errors") or []
        if errors:
            # Rule-level errors mean partial coverage, not a clean scan.
            result.partial(
                "Semgrep reported %d rule/parse error(s); coverage is incomplete." % len(errors)
            )

        payload["_engine"] = self.binary
        payload["_config"] = self.config
        result.payload = payload
        result.metadata["finding_count"] = len(payload.get("results") or [])
        return result.succeed().finish()


_KW = {"workspace", "config", "timeout", "binary"}


def _build_collector(**kwargs: Any) -> SemgrepCollector:
    return SemgrepCollector(**{k: v for k, v in kwargs.items() if k in _KW})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.semgrep_adapter import SemgrepAdapter

    return SemgrepAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Semgrep/OpenGrep pattern-based static analysis.",
    )
)
