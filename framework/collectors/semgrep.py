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

# Semgrep reports two different things in `errors`, and they mean different things
# for trust. A rule that failed to run leaves coverage unknown. A file the parser
# could not read is a NAMED, bounded gap: that file was not analysed, every other
# file still was. Collapsing both into "coverage is incomplete" discards every
# real finding whenever a single unparseable file exists -- common for template
# dialects a generic grammar does not implement.
_PARSE_ERROR_MARKERS = ("partialparsing", "syntaxerror", "syntax error", "lexical error")


def _error_text(err: Any) -> str:
    if isinstance(err, dict):
        return " ".join(
            str(err.get(k, "")) for k in ("type", "message", "short_msg", "long_msg")
        ).lower()
    return str(err).lower()


def _is_parse_error(err: Any) -> bool:
    text = _error_text(err)
    return any(marker in text for marker in _PARSE_ERROR_MARKERS)


def _error_path(err: Any) -> str:
    if isinstance(err, dict):
        path = err.get("path")
        if isinstance(path, str) and path:
            return path
    return ""


def _classify_errors(errors: List[Any]):
    """Split Semgrep errors into blocking failures and named unparsed files.

    Returns (blocking, unparsed_paths). An error is only treated as a bounded
    parse gap when it both looks like a parse error AND names the file it could
    not read -- an unattributable error is treated as blocking, so an unknown
    failure always fails closed.
    """
    blocking: List[Any] = []
    unparsed = set()
    for err in errors:
        path = _error_path(err)
        if _is_parse_error(err) and path:
            unparsed.add(os.path.basename(path) if os.path.isabs(path) else path)
        else:
            blocking.append(err)
    return blocking, unparsed


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
        blocking, unparsed = _classify_errors(errors)
        finding_count = len(payload.get("results") or [])

        result.metadata["error_count"] = len(errors)
        result.metadata["blocking_error_count"] = len(blocking)
        result.metadata["unparsed_files"] = sorted(unparsed)

        if blocking:
            # A rule failed to run or the engine errored. Coverage is unknown, so
            # the category must not be verified on this result.
            result.partial(
                "Semgrep reported %d blocking rule/engine error(s); coverage is incomplete."
                % len(blocking)
            )
        if unparsed:
            # A file the parser could not read was NOT analysed. That is a coverage
            # gap, not an engine failure: the rest of the scan is still valid, and
            # suppressing the whole category would discard every real finding.
            # It is only fail-closed-critical when the scan otherwise looks clean,
            # because "no findings" cannot be trusted while files went unread.
            message = (
                "Semgrep could not parse %d file(s), which were therefore NOT analysed: %s"
                % (len(unparsed), ", ".join(sorted(unparsed)[:10]))
            )
            if finding_count == 0:
                result.partial(
                    message + ". With no findings from the files that did parse, this scan "
                    "cannot be treated as clean."
                )
            else:
                result.warn(message + ". Findings from the files that did parse are reported.")

        payload["_engine"] = self.binary
        payload["_config"] = self.config
        payload["_unparsed_files"] = sorted(unparsed)
        result.payload = payload
        result.metadata["finding_count"] = finding_count
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
