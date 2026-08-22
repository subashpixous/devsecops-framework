"""Nuclei collector — template-driven detection of known exposures.

Runs in a deliberately conservative configuration: templates tagged as
intrusive, or of `dos`/`fuzzing` type, are excluded. Nuclei is used here to
detect *known* exposures on a live target, not to attack it.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "nuclei"
CATEGORY_KEY = "nuclei_templates"

ACCEPT_RC = (0,)
DEFAULT_TIMEOUT = 1800

# Excluded because they are destructive or noisy rather than diagnostic.
EXCLUDED_TAGS = "dos,fuzz,intrusive,brute-force"
EXCLUDED_TYPES = "dns"


class NucleiCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"target_url", "timeout", "severities"}

    def __init__(
        self,
        target_url: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        severities: str = "critical,high,medium,low",
    ) -> None:
        self.target_url = (target_url or "").strip()
        self.timeout = timeout
        self.severities = severities

    def collect(self) -> ScannerResult:
        result = self.new_result()

        if not self.target_url:
            return result.skip(
                "No deployed URL was supplied (input 'deployed_url'). Known-vulnerability probing "
                "did NOT run, so this category is unverified."
            ).finish()

        if not tool_available(TOOL):
            return result.fail(
                "nuclei is not installed or not on PATH. Known-vulnerability probing did NOT run, "
                "so this category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(TOOL, ("-version",))
        result.metadata["excluded_tags"] = EXCLUDED_TAGS

        handle, report_path = tempfile.mkstemp(prefix="nuclei-", suffix=".jsonl")
        os.close(handle)
        try:
            argv = [
                TOOL,
                "-u", self.target_url,
                "-jsonl",
                "-o", report_path,
                "-silent",
                "-no-color",
                "-severity", self.severities,
                "-exclude-tags", EXCLUDED_TAGS,
                "-exclude-type", EXCLUDED_TYPES,
                "-disable-update-check",
                "-timeout", "10",
                "-retries", "1",
            ]
            proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
            result.metadata["tool_run"] = proc.to_dict()

            if not accepted(proc, ACCEPT_RC):
                return result.fail("nuclei did not complete: %s" % proc.summary()).finish()

            records: List[Dict[str, Any]] = []
            malformed = 0
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            records.append(json.loads(line))
                        except ValueError:
                            malformed += 1

            if malformed:
                result.partial("%d nuclei output line(s) were not valid JSON and were skipped." % malformed)

            result.payload = {"_tool": TOOL, "_target": self.target_url, "findings": records}
            result.metadata["finding_count"] = len(records)
            return result.succeed().finish()
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass


def _build_collector(**kwargs: Any) -> NucleiCollector:
    mapped = dict(kwargs)
    if "deployed_url" in mapped and "target_url" not in mapped:
        mapped["target_url"] = mapped["deployed_url"]
    return NucleiCollector(**{k: v for k, v in mapped.items() if k in NucleiCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.nuclei_adapter import NucleiAdapter

    return NucleiAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Nuclei template-driven known-exposure detection (non-intrusive templates only).",
    )
)
