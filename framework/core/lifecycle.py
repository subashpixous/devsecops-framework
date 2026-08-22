"""Finding lifecycle, exceptions and accepted-risk expiry.

Implements the FINDING AGGREGATION stage of the approved pipeline:

    Normalize -> Fingerprint -> New / Existing / Fixed / False Positive /
                 Accepted Risk / Scanner Failed / Not Tested

`Scanner Failed` and `Not Tested` are category-level states owned by the status
engine; this module owns the per-finding states.

Two invariants are enforced here and covered by tests:

  * An EXPIRED exception never suppresses a finding. Expiry re-opens it and
    records why. Suppressions cannot rot into silent acceptance.
  * A FIXED finding is only asserted when the scanner that originally produced
    it ran successfully in this run. If that scanner failed, its absent findings
    are UNKNOWN, not fixed -- a broken scanner must never look like remediation.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .errors import PolicyError
from .schema import Finding, utc_now

# --- Lifecycle states --------------------------------------------------------

LIFECYCLE_NEW = "NEW"
LIFECYCLE_EXISTING = "EXISTING"
LIFECYCLE_FIXED = "FIXED"
LIFECYCLE_FALSE_POSITIVE = "FALSE_POSITIVE"
LIFECYCLE_ACCEPTED_RISK = "ACCEPTED_RISK"
LIFECYCLE_EXPIRED_EXCEPTION = "EXPIRED_EXCEPTION"
LIFECYCLE_UNKNOWN = "UNKNOWN"

LIFECYCLE_STATES = (
    LIFECYCLE_NEW,
    LIFECYCLE_EXISTING,
    LIFECYCLE_FIXED,
    LIFECYCLE_FALSE_POSITIVE,
    LIFECYCLE_ACCEPTED_RISK,
    LIFECYCLE_EXPIRED_EXCEPTION,
    LIFECYCLE_UNKNOWN,
)

# States that remove a finding from threshold evaluation.
SUPPRESSED_STATES = {LIFECYCLE_FALSE_POSITIVE, LIFECYCLE_ACCEPTED_RISK}

EXCEPTION_FALSE_POSITIVE = "false_positive"
EXCEPTION_ACCEPTED_RISK = "accepted_risk"


@dataclass
class Exception_:
    """One recorded suppression."""

    fingerprint: str
    kind: str
    reason: str = ""
    owner: str = ""
    expires: str = ""  # ISO date; empty means "no expiry declared"
    source: str = ""

    def is_expired(self, today: Optional[date] = None) -> bool:
        """An exception with no expiry date is treated as EXPIRED.

        Suppressions must be reviewed. An undated one has no review point, so it
        fails closed rather than lasting forever.
        """
        if not self.expires:
            return True
        today = today or datetime.now(timezone.utc).date()
        try:
            return date.fromisoformat(str(self.expires).strip()) < today
        except ValueError:
            # An unparsable date is not a licence to suppress.
            return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "reason": self.reason,
            "owner": self.owner,
            "expires": self.expires,
            "source": self.source,
        }


@dataclass
class LifecycleSummary:
    """Counts and detail for the aggregation stage."""

    new: int = 0
    existing: int = 0
    fixed: int = 0
    false_positive: int = 0
    accepted_risk: int = 0
    expired_exceptions: int = 0
    unknown: int = 0
    baseline_available: bool = False
    baseline_source: str = ""
    baseline_finding_count: int = 0
    exceptions_loaded: int = 0
    exceptions_source: str = ""
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    expired_exception_details: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": {
                "new": self.new,
                "existing": self.existing,
                "fixed": self.fixed,
                "false_positive": self.false_positive,
                "accepted_risk": self.accepted_risk,
                "expired_exceptions": self.expired_exceptions,
                "unknown": self.unknown,
            },
            "baseline_available": self.baseline_available,
            "baseline_source": self.baseline_source,
            "baseline_finding_count": self.baseline_finding_count,
            "exceptions_loaded": self.exceptions_loaded,
            "exceptions_source": self.exceptions_source,
            "fixed_findings": self.fixed_findings,
            "expired_exception_details": self.expired_exception_details,
            "notes": self.notes,
        }


def load_baseline(path: Optional[str]) -> Tuple[Dict[str, Dict[str, Any]], str, List[str]]:
    """Load a previous run's normalized-findings.json.

    Returns (by_fingerprint, source_description, notes). A missing or unreadable
    baseline is not an error -- it means every finding is NEW -- but it is
    always recorded so the report says so explicitly.
    """
    notes: List[str] = []
    if not path:
        return {}, "", ["No baseline supplied; every finding is reported as NEW and no FIXED state can be asserted."]
    if not os.path.exists(path):
        return {}, "", ["Baseline file %s not found; every finding is reported as NEW." % os.path.basename(path)]

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return {}, "", ["Baseline %s could not be read (%s); every finding is reported as NEW." % (os.path.basename(path), exc)]

    items = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return {}, "", ["Baseline %s has an unexpected shape; ignored." % os.path.basename(path)]

    by_fp: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if isinstance(item, dict) and item.get("fingerprint"):
            by_fp[item["fingerprint"]] = item
    return by_fp, os.path.basename(path), notes


def load_exceptions(path: Optional[str]) -> Tuple[Dict[str, Exception_], str, List[str]]:
    """Load the exceptions file (YAML or JSON).

    Shape:
        exceptions:
          - fingerprint: "abc123..."
            kind: accepted_risk | false_positive
            reason: "..."
            owner: "..."
            expires: "2026-12-31"
    """
    notes: List[str] = []
    if not path:
        return {}, "", []
    if not os.path.exists(path):
        return {}, "", ["Exceptions file %s not found; no suppressions applied." % os.path.basename(path)]

    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        if path.lower().endswith((".yml", ".yaml")):
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover
                raise PolicyError("PyYAML required to read %s: %s" % (path, exc)) from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
    except PolicyError:
        raise
    except Exception as exc:  # noqa: BLE001
        return {}, "", ["Exceptions file %s could not be parsed (%s); NO suppressions applied." % (os.path.basename(path), exc)]

    entries = data.get("exceptions") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return {}, "", ["Exceptions file %s has an unexpected shape; NO suppressions applied." % os.path.basename(path)]

    out: Dict[str, Exception_] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        fp = str(entry.get("fingerprint") or "").strip()
        kind = str(entry.get("kind") or "").strip().lower()
        if not fp:
            notes.append("An exception entry without a fingerprint was ignored.")
            continue
        if kind not in (EXCEPTION_FALSE_POSITIVE, EXCEPTION_ACCEPTED_RISK):
            notes.append("Exception %s has unknown kind %r and was ignored." % (fp[:12], kind))
            continue
        out[fp] = Exception_(
            fingerprint=fp,
            kind=kind,
            reason=str(entry.get("reason") or ""),
            owner=str(entry.get("owner") or ""),
            expires=str(entry.get("expires") or ""),
            source=os.path.basename(path),
        )
    return out, os.path.basename(path), notes


def apply_lifecycle(
    findings: List[Finding],
    baseline: Dict[str, Dict[str, Any]],
    baseline_source: str,
    exceptions: Dict[str, Exception_],
    exceptions_source: str,
    trustworthy_categories: Set[str],
    today: Optional[date] = None,
) -> LifecycleSummary:
    """Annotate findings with lifecycle state and compute the summary.

    `trustworthy_categories` is the set of scanner_category keys whose scanner
    completed successfully in this run. Only those may produce FIXED findings.
    """
    summary = LifecycleSummary(
        baseline_available=bool(baseline),
        baseline_source=baseline_source,
        baseline_finding_count=len(baseline),
        exceptions_loaded=len(exceptions),
        exceptions_source=exceptions_source,
    )

    current_fps: Set[str] = set()

    for finding in findings:
        fp = finding.fingerprint
        current_fps.add(fp)

        # 1. Baseline comparison sets NEW vs EXISTING.
        if baseline:
            if fp in baseline:
                finding.lifecycle = LIFECYCLE_EXISTING
                previous_first_seen = baseline[fp].get("first_seen")
                if previous_first_seen:
                    finding.first_seen = previous_first_seen
            else:
                finding.lifecycle = LIFECYCLE_NEW
        else:
            finding.lifecycle = LIFECYCLE_NEW

        # 2. Exceptions may suppress -- unless expired.
        exception = exceptions.get(fp)
        if exception:
            finding.exception_reason = exception.reason
            finding.exception_expires = exception.expires
            finding.exception_owner = exception.owner
            if exception.is_expired(today):
                finding.lifecycle = LIFECYCLE_EXPIRED_EXCEPTION
                summary.expired_exceptions += 1
                detail = exception.to_dict()
                detail["why"] = (
                    "no expiry date declared" if not exception.expires else "expired on %s" % exception.expires
                )
                detail["effect"] = "suppression NOT applied; finding counts against policy"
                summary.expired_exception_details.append(detail)
            elif exception.kind == EXCEPTION_FALSE_POSITIVE:
                finding.lifecycle = LIFECYCLE_FALSE_POSITIVE
            else:
                finding.lifecycle = LIFECYCLE_ACCEPTED_RISK

    # 3. FIXED: present in baseline, absent now -- but only where the scanner ran.
    if baseline:
        for fp, item in baseline.items():
            if fp in current_fps:
                continue
            category = str(item.get("scanner_category") or "")
            if category and category not in trustworthy_categories:
                summary.unknown += 1
                continue
            summary.fixed += 1
            summary.fixed_findings.append(
                {
                    "fingerprint": fp,
                    "tool": item.get("tool", ""),
                    "category": item.get("category", ""),
                    "severity": item.get("severity", ""),
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                    "description": item.get("description", ""),
                    "scanner_category": category,
                    "fixed_at": utc_now(),
                }
            )

    if summary.unknown:
        summary.notes.append(
            "%d baseline finding(s) are absent from this run but their scanner did not complete "
            "successfully. They are recorded as UNKNOWN, not FIXED -- a failed scanner must never "
            "look like remediation." % summary.unknown
        )

    # 4. Tally current-run states.
    for finding in findings:
        state = finding.lifecycle
        if state == LIFECYCLE_NEW:
            summary.new += 1
        elif state == LIFECYCLE_EXISTING:
            summary.existing += 1
        elif state == LIFECYCLE_FALSE_POSITIVE:
            summary.false_positive += 1
        elif state == LIFECYCLE_ACCEPTED_RISK:
            summary.accepted_risk += 1

    if not baseline:
        summary.notes.append(
            "No usable baseline was available, so NEW/EXISTING cannot be distinguished and no "
            "FIXED findings can be asserted. All open findings are reported as NEW."
        )
    if summary.expired_exceptions:
        summary.notes.append(
            "%d exception(s) have expired or carry no expiry date. Their suppressions were NOT "
            "applied and the findings count against policy." % summary.expired_exceptions
        )
    return summary


def is_suppressed(finding: Finding) -> bool:
    """True when a finding is validly suppressed and excluded from thresholds."""
    return getattr(finding, "lifecycle", "") in SUPPRESSED_STATES
