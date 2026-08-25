"""Gitleaks collector — committed secret detection.

SECURITY-CRITICAL PROPERTY OF THIS MODULE
-----------------------------------------
Gitleaks reports the secret it found, verbatim, in the `Secret` and `Match`
fields. Those fields are stripped here, before the payload is attached to the
ScannerResult and therefore before anything is written to disk or to a report.

A secret scanner that leaks the secrets it finds into a downloadable CI artifact
would create the exact exposure it exists to detect. The stripping is enforced
by unit test, not left to reviewer discipline.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core import scanpaths
from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "gitleaks"
CATEGORY_KEY = "secret_scanning"

# 0 = no leaks, 1 = leaks found. Both are completed scans.
ACCEPT_RC = (0, 1)
DEFAULT_TIMEOUT = 900

# Fields that carry raw secret material and must never survive collection.
SECRET_BEARING_FIELDS = ("Secret", "Match", "secret", "match")


def strip_secret_material(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove verbatim secret values, keeping everything needed to locate them.

    What is kept: rule, file, line, commit, author, date, entropy, fingerprint.
    What is removed: the secret itself and the surrounding matched text.
    """
    cleaned: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        safe = {k: v for k, v in record.items() if k not in SECRET_BEARING_FIELDS}
        # Preserve length as a non-reversible signal for triage.
        for field_name in ("Secret", "secret"):
            value = record.get(field_name)
            if isinstance(value, str) and value:
                safe["SecretLength"] = len(value)
                safe["SecretRedacted"] = True
                break
        cleaned.append(safe)
    return cleaned


class GitleaksCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY

    def __init__(
        self,
        workspace: str = ".",
        scan_history: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        config_path: Optional[str] = None,
    ) -> None:
        self.workspace = workspace
        self.scan_history = scan_history
        self.timeout = timeout
        self.config_path = config_path

    def collect(self) -> ScannerResult:
        result = self.new_result()

        is_git_repo = os.path.isdir(os.path.join(self.workspace, ".git"))
        mode = "git" if (self.scan_history and is_git_repo) else "dir"
        result.metadata["mode"] = mode
        # Secret scanning excludes nothing but version-control internals: a
        # credential committed inside a vendored directory or a built artefact is
        # exposed exactly as much as one committed at the root.
        plan = scanpaths.resolve(scanpaths.INTENT_SECRET)
        result.metadata["exclusions"] = plan.to_dict()
        # Declared BEFORE the availability guard, deliberately. The census credits
        # coverage only to a scan that completed, so declaring intent early cannot
        # inflate anything -- but it lets the report state exactly how much
        # coverage a missing gitleaks cost, instead of leaving it unquantified.
        result.metadata["coverage"] = {
            "exclusions": plan.to_dict(),
            "extensions": [],
            "unit": "repository files and git history",
            "unit_detail": {"mode": mode, "git_history": bool(self.scan_history and is_git_repo)},
        }

        if not tool_available(TOOL):
            return result.fail(
                "gitleaks is not installed or not on PATH. Secret scanning did NOT run, "
                "so this category is unverified."
            ).finish()

        result.metadata["version"] = tool_version(TOOL)
        if self.scan_history and not is_git_repo:
            result.partial(
                "Workspace is not a git repository; git history was NOT scanned. "
                "Only the working tree was covered."
            )

        handle, report_path = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
        os.close(handle)
        try:
            argv = [
                TOOL, mode, self.workspace,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner",
                "--exit-code", "1",
            ]
            if self.config_path and os.path.exists(self.config_path):
                argv += ["--config", self.config_path]
                result.metadata["config"] = os.path.basename(self.config_path)

            proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
            result.metadata["tool_run"] = proc.to_dict()

            if not accepted(proc, ACCEPT_RC):
                return result.fail("gitleaks did not complete: %s" % proc.summary()).finish()

            raw_text = ""
            try:
                if os.path.exists(report_path):
                    with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
                        raw_text = fh.read().strip()
            except OSError as exc:
                return result.fail("gitleaks report could not be read: %s" % exc).finish()

            if not raw_text:
                # An empty report with rc 0 legitimately means "no leaks found".
                records: List[Dict[str, Any]] = []
            else:
                try:
                    parsed = json.loads(raw_text)
                except ValueError as exc:
                    return result.fail("gitleaks report is not valid JSON: %s" % exc).finish()
                records = parsed if isinstance(parsed, list) else (parsed.get("findings") or [])

            # *** Strip secret material before it can reach disk. ***
            safe_records = strip_secret_material(records)

            result.payload = {
                "_tool": TOOL,
                "_mode": mode,
                "_secret_values_stripped": True,
                "findings": safe_records,
            }
            result.metadata["finding_count"] = len(safe_records)
            result.metadata["secret_values_stripped"] = True
            return result.succeed().finish()
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass


_KW = {"workspace", "scan_history", "timeout", "config_path"}


def _build_collector(**kwargs: Any) -> GitleaksCollector:
    return GitleaksCollector(**{k: v for k, v in kwargs.items() if k in _KW})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.gitleaks_adapter import GitleaksAdapter

    return GitleaksAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Gitleaks committed-secret detection (secret values stripped at collection).",
    )
)
