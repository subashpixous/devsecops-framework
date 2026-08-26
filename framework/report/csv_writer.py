"""CSV output — the complete finding list, in the tool teams actually triage in.

`final-report.json` already holds every finding, but nobody assigns work from a
JSON file. The Markdown and PDF reports are readable but truncated by design.
That leaves a gap exactly where remediation starts: a lead who needs to sort 400
findings by severity, filter to what is new, and hand each row to an owner.

This writer emits every finding, untruncated, one row each, with the fields that
support that workflow first and the provenance fields after. It adds an empty
`owner` column: the file is meant to be filled in and worked from.

Values are written through `csv` rather than assembled by hand, so a description
containing a comma, a quote or a newline cannot shift the columns -- silent
column drift in a security report is worse than no report.
"""

from __future__ import annotations

import csv
import os
from typing import Any, Dict, List, Sequence

# Ordered for triage, not for the schema: what is it, how bad, where, is it new,
# what do I do -- then the provenance a reader only needs when disputing a row.
COLUMNS: Sequence[str] = (
    "severity",
    # Exploitability first, next to severity: this is the pair a triager sorts
    # on. Empty means the data source was unavailable, NOT that the finding is
    # unexploited -- the report's enrichment section states which it was.
    "kev_listed",
    "epss_score",
    "epss_band",
    "cve_ids",
    "lifecycle",
    "status",
    "category",
    "tool",
    # Which OTHER scanners independently found the same defect. Corroboration is
    # evidence, so it travels with the row rather than living only in a summary.
    "also_detected_by",
    "correlation_id",
    "file",
    "line",
    "description",
    "remediation",
    "impact",
    "cwe",
    "owasp",
    "rule",
    "scanner_category",
    "endpoint",
    "evidence",
    "fingerprint",
    "first_seen",
    "last_seen",
    "commit",
    "branch",
    "environment",
    "exception_reason",
    "exception_expires",
    "exception_owner",
    # Deliberately empty. The file exists to be worked from.
    "owner",
    "target_date",
    "notes",
)

# Severity order for sorting, most urgent first. UNKNOWN sorts high on purpose:
# the policy fails it closed, so it must not be buried at the bottom of the file.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}


def _cell(value: Any) -> str:
    """Flatten one field to a single-line string.

    Newlines are replaced rather than quoted: spreadsheet software renders an
    embedded newline as a row that looks broken, and every consumer of this file
    is a spreadsheet.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join(str(v) for v in value)
    text = str(value)
    return " ".join(text.split())


def _sort_key(finding: Dict[str, Any]):
    severity = str(finding.get("severity") or "UNKNOWN").upper()
    # New findings first within a severity: they are what this change introduced
    # and the only ones a pull request can reasonably be asked to fix.
    lifecycle = str(finding.get("lifecycle") or "").upper()
    return (
        _SEVERITY_RANK.get(severity, 9),
        0 if lifecycle == "NEW" else 1,
        str(finding.get("file") or ""),
        int(finding.get("line") or 0) if str(finding.get("line") or "0").isdigit() else 0,
    )


def build_rows(report: Dict[str, Any]) -> List[Dict[str, str]]:
    findings = list((report.get("findings") or {}).get("items") or [])
    findings.sort(key=_sort_key)

    # Whether the exploitability sources were actually reachable. `kev_listed`
    # defaults to False on every finding, and rendering that as "False" when the
    # KEV feed was unreachable would assert "not known-exploited" on evidence we
    # never had. When the source was unavailable the cell says so instead.
    enrichment = report.get("enrichment") or {}
    kev_known = enrichment.get("kev_status") == "KEV_AVAILABLE"
    epss_known = enrichment.get("epss_status") == "EPSS_AVAILABLE"

    rows: List[Dict[str, str]] = []
    for finding in findings:
        row = {column: _cell(finding.get(column)) for column in COLUMNS}

        if not kev_known:
            row["kev_listed"] = "NOT_ESTABLISHED"
        else:
            row["kev_listed"] = "YES" if finding.get("kev_listed") else "no"

        if not epss_known and not row["epss_score"]:
            row["epss_score"] = "NOT_ESTABLISHED"
            row["epss_band"] = "NOT_ESTABLISHED"
        elif not row["epss_score"]:
            # EPSS was reachable but had no score for this CVE, which is still
            # not a low score.
            row["epss_score"] = "NO_SCORE"
            row["epss_band"] = "NOT_ESTABLISHED"

        # Columns the schema does not carry stay empty for a human to fill.
        row["owner"] = ""
        row["target_date"] = ""
        row["notes"] = ""
        rows.append(row)
    return rows


def write_csv(report: Dict[str, Any], output_dir: str, filename: str = "findings.csv") -> str:
    """Write every finding. Never truncates -- that is this file's whole purpose."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    rows = build_rows(report)
    # newline="" is required by the csv module on Windows; without it every row
    # is followed by a blank one.
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path
