"""Common Finding Schema.

Every scanner in every phase normalises into this one shape. The keys listed in
APPROVED_SCHEMA_KEYS are the approved contract and are emitted verbatim, in order,
for every finding. Framework extension keys are additive and always appear after
the approved keys so downstream consumers written against the approved schema keep
working unchanged.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --- Approved contract -------------------------------------------------------

APPROVED_SCHEMA_KEYS = [
    "fingerprint",
    "tool",
    "category",
    "severity",
    "cwe",
    "owasp",
    "file",
    "line",
    "endpoint",
    "evidence",
    "description",
    "impact",
    "remediation",
    "first_seen",
    "last_seen",
    "status",
    "environment",
    "commit",
    "branch",
]

EXTENSION_SCHEMA_KEYS = [
    "native_id",
    "rule",
    "raw_severity",
    "tags",
    "component",
    "effort",
    "phase",
    "scanner_category",
    "lifecycle",
    "exception_reason",
    "exception_expires",
    "exception_owner",
    # Exploitability context (framework.core.prioritization). Absent when the
    # data source was unavailable -- never defaulted to a number, because a
    # score of 0.0 sorts as harmless and "unknown" must not.
    "cve_ids",
    "epss_score",
    "epss_percentile",
    "epss_band",
    "kev_listed",
    "kev_date_added",
    "kev_due_date",
    # Cross-scanner corroboration (framework.core.correlation). Additive only:
    # correlated findings are never merged or removed.
    "correlation_id",
    "also_detected_by",
]

# --- Canonical severity ------------------------------------------------------

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"
SEVERITY_UNKNOWN = "UNKNOWN"

# Ordered most severe first. UNKNOWN sorts with HIGH deliberately: an
# unclassifiable finding must never be treated as harmless.
SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_UNKNOWN,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# --- Finding status ----------------------------------------------------------

STATUS_OPEN = "OPEN"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_REOPENED = "REOPENED"
STATUS_TO_REVIEW = "TO_REVIEW"
STATUS_RESOLVED = "RESOLVED"
STATUS_ACCEPTED = "ACCEPTED"

# Statuses that count against policy thresholds. ACCEPTED/RESOLVED do not.
# Phase 4 introduces accepted-risk expiry; until then ACCEPTED can only originate
# from the upstream scanner, never from framework state.
OPEN_STATUSES = {STATUS_OPEN, STATUS_CONFIRMED, STATUS_REOPENED, STATUS_TO_REVIEW}

_WHITESPACE = re.compile(r"\s+")


def utc_now() -> str:
    """ISO-8601 UTC timestamp used for first_seen/last_seen and run metadata."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_severity(value: Optional[str]) -> str:
    """Map any scanner severity vocabulary onto the canonical scale.

    Unrecognised input becomes UNKNOWN, never INFO -- downgrading an unknown
    severity would create a silent gap.
    """
    if not value:
        return SEVERITY_UNKNOWN
    token = str(value).strip().upper()
    mapping = {
        # SonarQube legacy issue severities
        "BLOCKER": SEVERITY_CRITICAL,
        "CRITICAL": SEVERITY_CRITICAL,
        "MAJOR": SEVERITY_MEDIUM,
        "MINOR": SEVERITY_LOW,
        "INFO": SEVERITY_INFO,
        # SonarQube Clean Code impact severities + common scanner vocabularies
        "HIGH": SEVERITY_HIGH,
        "MEDIUM": SEVERITY_MEDIUM,
        "LOW": SEVERITY_LOW,
        "MODERATE": SEVERITY_MEDIUM,
        "WARNING": SEVERITY_MEDIUM,
        "ERROR": SEVERITY_HIGH,
        "NOTE": SEVERITY_LOW,
        "NONE": SEVERITY_INFO,
        "NEGLIGIBLE": SEVERITY_INFO,
        "UNKNOWN": SEVERITY_UNKNOWN,
    }
    return mapping.get(token, SEVERITY_UNKNOWN)


def compute_fingerprint(
    tool: str,
    rule: str,
    file_path: str,
    category: str,
    description: str,
    discriminator: str = "",
) -> str:
    """Stable identity for ONE finding across runs.

    `discriminator` distinguishes independent occurrences that share every other
    attribute. Without it, five different secrets on five different lines of the
    same file, found by the same rule, collapse into one identity -- and a single
    exception entry would then suppress all five.

    That was the original design: line number was excluded so unrelated edits
    could not churn fingerprints and disturb the lifecycle model. Measured
    against a real project the trade was wrong -- 83 of 156 findings shared an
    identity across 21 groups. Churn costs accuracy in the NEW/EXISTING split;
    collision silently hides real findings. Only one of those is a safety
    property, so uniqueness wins and the churn is accepted.
    """
    normalised_description = _WHITESPACE.sub(" ", (description or "").strip().lower())
    seed = "|".join(
        [
            (tool or "").strip().lower(),
            (rule or "").strip().lower(),
            (file_path or "").strip().replace("\\", "/").lower(),
            (category or "").strip().lower(),
            normalised_description,
            (discriminator or "").strip().lower(),
        ]
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def occurrence_discriminator(native_id: str, line: Any, component: str) -> str:
    """The parts that tell two otherwise-identical findings apart.

    All three are needed, and each earns its place against real scanner output:

      native_id  the tool's own identity, unique per occurrence for some tools
      line       position in a file -- separates repeated hits of one rule
      component  the affected thing -- separates one CVE affecting two packages,
                 which share a file, a line (0) and a native id
    """
    return "|".join(
        [
            (native_id or "").strip(),
            str(line or 0).strip(),
            (component or "").strip(),
        ]
    )


@dataclass
class Finding:
    """One normalised security finding."""

    # Approved schema
    fingerprint: str = ""
    tool: str = ""
    category: str = ""
    severity: str = SEVERITY_UNKNOWN
    cwe: str = ""
    owasp: str = ""
    file: str = ""
    line: int = 0
    endpoint: str = ""
    evidence: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = STATUS_OPEN
    environment: str = ""
    commit: str = ""
    branch: str = ""

    # Framework extensions (additive)
    native_id: str = ""
    rule: str = ""
    raw_severity: str = ""
    tags: List[str] = field(default_factory=list)
    component: str = ""
    effort: str = ""
    phase: int = 0
    scanner_category: str = ""

    # Phase 4 lifecycle (set by framework.core.lifecycle)
    lifecycle: str = "UNKNOWN"
    exception_reason: str = ""
    exception_expires: str = ""
    exception_owner: str = ""

    # Exploitability context (set by framework.core.prioritization).
    # None means "not established", which is deliberately distinct from a low
    # score: one says nobody looked, the other says somebody looked and it is
    # unlikely. Rendering them identically would be a silent gap.
    cve_ids: List[str] = field(default_factory=list)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_band: str = ""
    kev_listed: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""

    # Cross-scanner corroboration. `also_detected_by` names the OTHER tools that
    # independently reported the same defect; this finding still stands on its
    # own with its own fingerprint and lifecycle.
    correlation_id: str = ""
    also_detected_by: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = normalise_severity(self.severity or self.raw_severity)
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.tool,
                self.rule,
                self.file,
                self.category,
                self.description,
                occurrence_discriminator(self.native_id, self.line, self.component),
            )
        stamp = utc_now()
        if not self.first_seen:
            self.first_seen = stamp
        if not self.last_seen:
            self.last_seen = stamp
        try:
            self.line = int(self.line or 0)
        except (TypeError, ValueError):
            self.line = 0

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, SEVERITY_RANK[SEVERITY_UNKNOWN])

    def to_dict(self) -> Dict[str, Any]:
        """Serialise with approved keys first, in approved order."""
        raw = asdict(self)
        ordered: Dict[str, Any] = {}
        for key in APPROVED_SCHEMA_KEYS:
            ordered[key] = raw[key]
        for key in EXTENSION_SCHEMA_KEYS:
            ordered[key] = raw[key]
        return ordered


def severity_breakdown(findings: List[Finding], open_only: bool = True) -> Dict[str, int]:
    """Count findings per canonical severity. Always returns every level."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        if open_only and not finding.is_open:
            continue
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then deterministic by file/line/fingerprint."""
    return sorted(
        findings,
        key=lambda f: (f.severity_rank, f.file, f.line, f.fingerprint),
    )
