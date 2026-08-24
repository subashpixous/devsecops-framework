"""Semgrep / OpenGrep collector — pattern-based SAST.

Runs the scanner over the workspace and captures its JSON report. Semgrep exits
1 when it finds something, which is a successful scan, not a failure.

OpenGrep is a drop-in fork; if `semgrep` is absent the collector falls back to
`opengrep` and records which engine actually ran.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence

from ..core import scanpaths
from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "semgrep"
CATEGORY_KEY = "sast_semgrep"

# 0 = clean, 1 = findings present. Both mean the scan completed.
ACCEPT_RC = (0, 1)

# `p/default` is Semgrep's high-precision starter set: it is tuned to almost
# never produce a false positive, which also means it does not look for most of
# what a security review needs. Running it and calling the category PASS would
# be a clean result from a scan that was never asked the security questions.
#
# The security packs below are the ones whose whole purpose is those questions.
# A project that wants something else sets SEMGREP_RULES and the choice is
# recorded on the result either way.
SECURITY_CONFIGS = ("p/security-audit", "p/owasp-top-ten")

# Language packs, added only for languages actually present. Semgrep accepts
# repeated --config flags and unions the rules.
LANGUAGE_CONFIGS = {
    "php": "p/php",
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "java": "p/java",
    "go": "p/golang",
    "csharp": "p/csharp",
    "ruby": "p/ruby",
    "kotlin": "p/kotlin",
    "scala": "p/scala",
    "swift": "p/swift",
    "rust": "p/rust",
}

DEFAULT_TIMEOUT = 1800

# File types this engine is credited with reading, for the coverage manifest.
# Narrower than what Semgrep advertises: this list backs a coverage claim.
READS_EXTENSIONS = (
    ".php", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt",
    ".go", ".rb", ".cs", ".rs", ".swift", ".scala", ".vue", ".html", ".htm",
    ".sh", ".bash",
)


def resolve_configs(languages: Sequence[str]) -> List[str]:
    """Security packs plus a language pack for each language actually present."""
    configs = list(SECURITY_CONFIGS)
    for language in languages or ():
        pack = LANGUAGE_CONFIGS.get(str(language).lower())
        if pack and pack not in configs:
            configs.append(pack)
    return configs

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
        languages: Optional[Sequence[str]] = None,
        include_dependencies: bool = False,
    ) -> None:
        self.workspace = workspace
        self.languages = list(languages or ())
        # SEMGREP_RULES lets a project pin its own ruleset without code changes.
        override = config or os.environ.get("SEMGREP_RULES") or ""
        self.configs = [c.strip() for c in override.split(",") if c.strip()] or \
            resolve_configs(self.languages)
        self.config = ",".join(self.configs)
        self.config_source = "override" if override else "framework default (security packs)"
        self.timeout = timeout
        self.binary = binary or (TOOL if tool_available(TOOL) else "opengrep")
        # What this scan will and will not read, decided from the languages
        # present rather than from a fixed list, and reported either way.
        self.exclusions = scanpaths.resolve(
            scanpaths.INTENT_SAST, self.languages, include_dependencies=include_dependencies
        )

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["engine"] = self.binary
        result.metadata["config"] = self.config
        result.metadata["config_source"] = self.config_source
        result.metadata["languages"] = self.languages
        result.metadata["exclusions"] = self.exclusions.to_dict()
        # Declared reach, consumed by the file-level coverage manifest. Declaring
        # it is not a claim that the scan succeeded -- the manifest credits
        # coverage only when the ScannerResult itself is trustworthy.
        result.metadata["coverage"] = {
            "exclusions": self.exclusions.to_dict(),
            "extensions": list(READS_EXTENSIONS),
        }
        if self.exclusions.loses_coverage:
            result.warn(self.exclusions.coverage_note())

        if not tool_available(self.binary):
            return result.fail(
                "Neither 'semgrep' nor 'opengrep' is installed or on PATH. "
                "Static analysis by this engine did NOT run, so this category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(self.binary)

        argv = [
            self.binary, "scan",
            "--json",
            "--quiet",
            "--metrics", "off",
            "--timeout", "60",
            "--max-target-bytes", "2000000",
        ]
        for config in self.configs:
            argv += ["--config", config]
        for pattern in self.exclusions.patterns:
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

        result.metadata["max_target_bytes"] = 2000000
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
        payload["_exclusions"] = self.exclusions.to_dict()
        payload["_unparsed_files"] = sorted(unparsed)
        result.payload = payload
        result.metadata["finding_count"] = finding_count
        return result.succeed().finish()


_KW = {"workspace", "config", "timeout", "binary", "languages", "include_dependencies"}


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
