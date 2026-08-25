"""Exploitability enrichment: EPSS and the CISA KEV catalogue.

Severity answers "how bad would this be if exploited". It does not answer "is
anyone exploiting it", and a list of 400 CRITICAL findings sorted by severity is
a list nobody triages. Two public data sets answer the second question:

  EPSS  a daily probability that a CVE will be exploited in the next 30 days,
        published by FIRST. Turns a wall of CRITICALs into an ordering.
  KEV   CISA's catalogue of vulnerabilities with confirmed in-the-wild
        exploitation. Membership is a fact, not a prediction.

DESIGN CONSTRAINTS
------------------
1. **Never fabricate.** A CVE with no EPSS score gets no score. It is not 0.0,
   which would sort it as harmless, and it is not 1.0. It is absent, and the
   report says the data was unavailable.

2. **Never mandatory.** Both sources are network calls to third parties. A
   runner with no egress, a rate limit, or an outage must degrade the *report*,
   never fail the *run*. Enrichment failure is recorded as EPSS_UNAVAILABLE /
   KEV_UNAVAILABLE and the findings pass through untouched.

3. **Never a verdict input.** Enrichment orders findings; it does not decide
   them. A KEV-listed finding is not "more failed" than a non-KEV one -- the
   policy thresholds already decided that. Letting a network fetch influence a
   security verdict would make the verdict depend on third-party uptime.

The distinction in (3) is the reason this module is separate from the status
engine and is applied after it.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# --- Availability states -----------------------------------------------------

EPSS_AVAILABLE = "EPSS_AVAILABLE"
EPSS_UNAVAILABLE = "EPSS_UNAVAILABLE"
EPSS_DISABLED = "EPSS_DISABLED"
EPSS_NOT_APPLICABLE = "EPSS_NOT_APPLICABLE"

KEV_AVAILABLE = "KEV_AVAILABLE"
KEV_UNAVAILABLE = "KEV_UNAVAILABLE"
KEV_DISABLED = "KEV_DISABLED"
KEV_NOT_APPLICABLE = "KEV_NOT_APPLICABLE"

EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
KEV_ENDPOINT = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

DEFAULT_TIMEOUT = 15
# The EPSS API takes a comma-separated CVE list; keep each URL comfortably short.
EPSS_BATCH_SIZE = 100
# A repository with thousands of distinct CVEs must not turn enrichment into the
# slowest part of the run. The cap is reported when it bites.
MAX_CVES = 2000

USER_AGENT = "devsecops-framework/prioritization (read-only public data)"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# EPSS probability bands, used for the human-readable label only. The numeric
# score is always reported alongside, so the label never has to be trusted.
EPSS_BANDS = (
    (0.36, "high"),      # roughly the top 1% of all scored CVEs
    (0.10, "elevated"),
    (0.01, "moderate"),
    (0.0, "low"),
)


def extract_cves(*values: Any) -> List[str]:
    """Pull every CVE identifier out of arbitrary finding text.

    Scanners put the CVE in different places -- Trivy in the native id, Semgrep
    in the message, others in tags -- so the caller passes everything it has and
    this finds them. Returns upper-cased, de-duplicated, order-preserved.
    """
    found: List[str] = []
    seen: Set[str] = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            text = " ".join(str(item) for item in value)
        else:
            text = str(value)
        for match in CVE_PATTERN.findall(text):
            upper = match.upper()
            if upper not in seen:
                seen.add(upper)
                found.append(upper)
    return found


def epss_band(score: Optional[float]) -> str:
    if score is None:
        return "NOT_ESTABLISHED"
    for threshold, label in EPSS_BANDS:
        if score >= threshold:
            return label
    return "low"


@dataclass
class EnrichmentResult:
    """What enrichment was able to establish, and what it could not."""

    epss_status: str = EPSS_NOT_APPLICABLE
    kev_status: str = KEV_NOT_APPLICABLE
    epss_reason: str = ""
    kev_reason: str = ""
    epss_scores: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    kev_entries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    cves_seen: int = 0
    cves_scored: int = 0
    kev_matches: int = 0
    findings_enriched: int = 0
    notes: List[str] = field(default_factory=list)
    source_epss: str = ""
    source_kev: str = ""

    @property
    def available(self) -> bool:
        return self.epss_status == EPSS_AVAILABLE or self.kev_status == KEV_AVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epss_status": self.epss_status,
            "epss_reason": self.epss_reason,
            "epss_source": self.source_epss,
            "kev_status": self.kev_status,
            "kev_reason": self.kev_reason,
            "kev_source": self.source_kev,
            "cves_seen": self.cves_seen,
            "cves_scored": self.cves_scored,
            "kev_matches": self.kev_matches,
            "findings_enriched": self.findings_enriched,
            "notes": self.notes,
            "statement": self.statement(),
        }

    def statement(self) -> str:
        """The sentence the report needs, with no interpretation required."""
        parts = []
        if self.epss_status == EPSS_AVAILABLE:
            parts.append(
                "EPSS exploit-probability scores were retrieved for %d of %d distinct CVE(s)"
                % (self.cves_scored, self.cves_seen)
            )
        elif self.epss_status == EPSS_UNAVAILABLE:
            parts.append(
                "EPSS scores were NOT available (%s), so no finding carries an exploit "
                "probability in this run" % self.epss_reason
            )
        elif self.epss_status == EPSS_DISABLED:
            parts.append("EPSS enrichment was disabled for this run")

        if self.kev_status == KEV_AVAILABLE:
            parts.append(
                "the CISA KEV catalogue was retrieved and matched %d finding CVE(s)"
                % self.kev_matches
            )
        elif self.kev_status == KEV_UNAVAILABLE:
            parts.append(
                "the CISA KEV catalogue was NOT available (%s), so known-exploited status is "
                "NOT_ESTABLISHED for every finding in this run" % self.kev_reason
            )
        elif self.kev_status == KEV_DISABLED:
            parts.append("KEV enrichment was disabled for this run")

        if not parts:
            return (
                "No CVE-bearing findings were produced, so exploitability enrichment did not "
                "apply to this run."
            )
        return (parts[0][0].upper() + parts[0][1:]) + (
            ("; " + "; ".join(parts[1:])) if len(parts) > 1 else ""
        ) + "."


def _fetch_json(url: str, timeout: int) -> Any:
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def load_epss(
    cves: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    offline_path: str = "",
) -> "tuple[Dict[str, Dict[str, Any]], str, str, str]":
    """Fetch EPSS scores. Returns (scores, status, reason, source)."""
    if not cves:
        return {}, EPSS_NOT_APPLICABLE, "no CVE-bearing findings", ""

    if offline_path:
        try:
            with open(offline_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            scores = _parse_epss(raw)
            return scores, EPSS_AVAILABLE, "", "local file %s" % os.path.basename(offline_path)
        except (OSError, ValueError) as exc:
            return {}, EPSS_UNAVAILABLE, "local EPSS file unreadable: %s" % exc, ""

    scores: Dict[str, Dict[str, Any]] = {}
    for index in range(0, len(cves), EPSS_BATCH_SIZE):
        batch = cves[index:index + EPSS_BATCH_SIZE]
        url = "%s?cve=%s" % (EPSS_ENDPOINT, ",".join(batch))
        try:
            payload = _fetch_json(url, timeout)
        except urllib.error.HTTPError as exc:
            return scores, EPSS_UNAVAILABLE, "HTTP %s from the EPSS API" % exc.code, EPSS_ENDPOINT
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return scores, EPSS_UNAVAILABLE, "the EPSS API was unreachable: %s" % exc, EPSS_ENDPOINT
        except ValueError as exc:
            return scores, EPSS_UNAVAILABLE, "the EPSS API returned malformed JSON: %s" % exc, EPSS_ENDPOINT
        scores.update(_parse_epss(payload))

    return scores, EPSS_AVAILABLE, "", EPSS_ENDPOINT


def _parse_epss(payload: Any) -> Dict[str, Dict[str, Any]]:
    """Read the FIRST EPSS response shape, tolerating absent fields."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(payload, dict):
        return out
    for entry in payload.get("data") or []:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cve") or "").upper()
        if not cve:
            continue
        try:
            score = float(entry.get("epss"))
        except (TypeError, ValueError):
            continue  # a score we cannot parse is a score we do not have
        try:
            percentile = float(entry.get("percentile"))
        except (TypeError, ValueError):
            percentile = None
        out[cve] = {
            "score": score,
            "percentile": percentile,
            "date": str(entry.get("date") or ""),
        }
    return out


def load_kev(
    timeout: int = DEFAULT_TIMEOUT,
    offline_path: str = "",
) -> "tuple[Dict[str, Dict[str, Any]], str, str, str]":
    """Fetch the CISA KEV catalogue. Returns (entries, status, reason, source)."""
    if offline_path:
        try:
            with open(offline_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            return _parse_kev(raw), KEV_AVAILABLE, "", "local file %s" % os.path.basename(offline_path)
        except (OSError, ValueError) as exc:
            return {}, KEV_UNAVAILABLE, "local KEV file unreadable: %s" % exc, ""

    try:
        payload = _fetch_json(KEV_ENDPOINT, timeout)
    except urllib.error.HTTPError as exc:
        return {}, KEV_UNAVAILABLE, "HTTP %s from the CISA KEV feed" % exc.code, KEV_ENDPOINT
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {}, KEV_UNAVAILABLE, "the CISA KEV feed was unreachable: %s" % exc, KEV_ENDPOINT
    except ValueError as exc:
        return {}, KEV_UNAVAILABLE, "the CISA KEV feed returned malformed JSON: %s" % exc, KEV_ENDPOINT

    return _parse_kev(payload), KEV_AVAILABLE, "", KEV_ENDPOINT


def _parse_kev(payload: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(payload, dict):
        return out
    for entry in payload.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "").upper()
        if not cve:
            continue
        out[cve] = {
            "date_added": str(entry.get("dateAdded") or ""),
            "due_date": str(entry.get("dueDate") or ""),
            "vendor_project": str(entry.get("vendorProject") or ""),
            "product": str(entry.get("product") or ""),
            "known_ransomware": str(entry.get("knownRansomwareCampaignUse") or ""),
            "required_action": str(entry.get("requiredAction") or ""),
        }
    return out


def enrich_findings(
    findings: Sequence[Any],
    enable_epss: bool = True,
    enable_kev: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    epss_file: str = "",
    kev_file: str = "",
) -> EnrichmentResult:
    """Attach exploitability context to findings, in place.

    Returns an EnrichmentResult describing what was and was not established.
    Never raises: enrichment is context, and losing context must not lose a run.
    """
    outcome = EnrichmentResult()

    # 1. Collect every distinct CVE across all findings.
    by_cve: Dict[str, List[Any]] = {}
    for finding in findings:
        cves = extract_cves(
            getattr(finding, "native_id", ""),
            getattr(finding, "rule", ""),
            getattr(finding, "description", ""),
            getattr(finding, "component", ""),
            getattr(finding, "tags", ()),
            getattr(finding, "evidence", ""),
        )
        if not cves:
            continue
        # The finding carries every CVE it mentions; the first is treated as
        # primary for sorting, and all are recorded.
        setattr(finding, "cve_ids", list(cves))
        for cve in cves:
            by_cve.setdefault(cve, []).append(finding)

    ordered_cves = sorted(by_cve)
    outcome.cves_seen = len(ordered_cves)

    if not ordered_cves:
        outcome.epss_status = EPSS_NOT_APPLICABLE if enable_epss else EPSS_DISABLED
        outcome.kev_status = KEV_NOT_APPLICABLE if enable_kev else KEV_DISABLED
        return outcome

    if len(ordered_cves) > MAX_CVES:
        outcome.notes.append(
            "This run produced %d distinct CVEs; enrichment was capped at %d. The remainder "
            "carry no EPSS score, which is NOT the same as a low score."
            % (len(ordered_cves), MAX_CVES)
        )
        ordered_cves = ordered_cves[:MAX_CVES]

    # 2. EPSS.
    if enable_epss:
        try:
            scores, status, reason, source = load_epss(ordered_cves, timeout, epss_file)
        except Exception as exc:  # noqa: BLE001 - context must never break a run
            scores, status, reason, source = {}, EPSS_UNAVAILABLE, "unexpected error: %s" % exc, ""
        outcome.epss_scores = scores
        outcome.epss_status = status
        outcome.epss_reason = reason
        outcome.source_epss = source
        outcome.cves_scored = len(scores)
    else:
        outcome.epss_status = EPSS_DISABLED
        outcome.epss_reason = "disabled by configuration"

    # 3. KEV.
    if enable_kev:
        try:
            entries, status, reason, source = load_kev(timeout, kev_file)
        except Exception as exc:  # noqa: BLE001
            entries, status, reason, source = {}, KEV_UNAVAILABLE, "unexpected error: %s" % exc, ""
        outcome.kev_entries = entries
        outcome.kev_status = status
        outcome.kev_reason = reason
        outcome.source_kev = source
    else:
        outcome.kev_status = KEV_DISABLED
        outcome.kev_reason = "disabled by configuration"

    # 4. Apply. A CVE with no data gets no attribute rather than a zero.
    enriched: Set[int] = set()
    for cve, related in by_cve.items():
        epss = outcome.epss_scores.get(cve)
        kev = outcome.kev_entries.get(cve)
        if kev:
            outcome.kev_matches += 1
        for finding in related:
            if epss is not None:
                existing = getattr(finding, "epss_score", None)
                # A finding citing several CVEs takes the worst of them: the
                # attacker only needs one.
                if existing is None or epss["score"] > existing:
                    setattr(finding, "epss_score", epss["score"])
                    setattr(finding, "epss_percentile", epss["percentile"])
                    setattr(finding, "epss_band", epss_band(epss["score"]))
                enriched.add(id(finding))
            if kev:
                setattr(finding, "kev_listed", True)
                setattr(finding, "kev_date_added", kev["date_added"])
                setattr(finding, "kev_due_date", kev["due_date"])
                setattr(finding, "kev_ransomware", kev["known_ransomware"])
                enriched.add(id(finding))

    outcome.findings_enriched = len(enriched)
    return outcome


def exploitability_rank(finding: Any) -> tuple:
    """Sort key: known-exploited first, then by EPSS, then by severity.

    Findings with no enrichment data sort *after* scored ones of the same
    severity rather than being treated as low risk -- absence of a score is
    absence of information, not evidence of safety.
    """
    kev = 0 if getattr(finding, "kev_listed", False) else 1
    score = getattr(finding, "epss_score", None)
    epss = -score if isinstance(score, float) else 0.0
    has_score = 0 if isinstance(score, float) else 1
    severity_rank = getattr(finding, "severity_rank", 99)
    return (kev, severity_rank, has_score, epss, getattr(finding, "file", ""))
