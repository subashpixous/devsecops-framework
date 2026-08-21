"""Collector contract.

A Collector talks to exactly one scanner backend and returns a ScannerResult
describing what happened, plus raw payload written to disk as evidence. A
collector NEVER decides a security verdict and NEVER raises past its own
boundary: every failure becomes a ScannerResult with status FAILED or PARTIAL,
which the status engine turns into NOT_VERIFIED.
"""

from __future__ import annotations

import abc
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.categories import (
    SCANNER_FAILED,
    SCANNER_OK,
    SCANNER_PARTIAL,
    SCANNER_SKIPPED,
)
from ..core.schema import utc_now


@dataclass
class ScannerResult:
    """Execution record for one scanner. Evidence for the report."""

    tool: str
    category_key: str
    status: str = SCANNER_FAILED  # fail closed by default
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_path: str = ""
    payload: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_trustworthy(self) -> bool:
        """Only a clean OK permits a category to be asserted PASS."""
        return self.status == SCANNER_OK and not self.errors

    def fail(self, message: str) -> "ScannerResult":
        self.status = SCANNER_FAILED
        self.errors.append(message)
        return self

    def partial(self, message: str) -> "ScannerResult":
        # A already-failed scan does not get upgraded to partial.
        if self.status != SCANNER_FAILED:
            self.status = SCANNER_PARTIAL
        self.warnings.append(message)
        return self

    def skip(self, message: str) -> "ScannerResult":
        self.status = SCANNER_SKIPPED
        self.warnings.append(message)
        return self

    def succeed(self) -> "ScannerResult":
        if not self.errors:
            self.status = SCANNER_OK
        return self

    def finish(self) -> "ScannerResult":
        self.finished_at = utc_now()
        return self

    def write_raw(self, directory: str, filename: str) -> str:
        """Persist the raw scanner payload as evidence."""
        if self.payload is None:
            return ""
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, filename)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.payload, handle, indent=2, sort_keys=True)
        self.raw_path = path
        return path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "category_key": self.category_key,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "errors": self.errors,
            "warnings": self.warnings,
            "raw_path": os.path.basename(self.raw_path) if self.raw_path else "",
            "metadata": self.metadata,
        }


class Collector(abc.ABC):
    """Base class for all scanner collectors."""

    tool: str = "unknown"
    category_key: str = ""

    @abc.abstractmethod
    def collect(self) -> ScannerResult:
        """Run the scan / fetch results. Must not raise."""

    def new_result(self) -> ScannerResult:
        return ScannerResult(tool=self.tool, category_key=self.category_key)
