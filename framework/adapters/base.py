"""Adapter contract: raw scanner payload -> common Finding schema.

Adapters are pure transformations. They never call the network and never decide a
verdict. If a payload cannot be trusted the adapter reports that back on the
ScannerResult (degrading it to PARTIAL/FAILED) rather than silently returning an
empty finding list -- an empty list would otherwise look like a clean scan.
"""

from __future__ import annotations

import abc
from typing import List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding


class Adapter(abc.ABC):
    """Base class for all scanner adapters."""

    tool: str = "unknown"
    category_key: str = ""

    @abc.abstractmethod
    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:
        """Convert a ScannerResult payload into normalised findings.

        Implementations must stamp commit / branch / environment from `context`
        onto every finding so each one is traceable to the exact run.
        """

    def summarize_gate(self, result: ScannerResult) -> dict:
        """Optional: expose an upstream gate/verdict from this tool.

        Default is an empty mapping, so a tool without a gate concept contributes
        nothing rather than an implicit pass.
        """
        return {}

    def stamp(self, finding: Finding, context: RunContext) -> Finding:
        finding.commit = context.commit
        finding.branch = context.branch
        finding.environment = context.environment
        return finding
