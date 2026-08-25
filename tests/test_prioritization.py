"""Exploitability enrichment contract tests.

The rules this module must never break:

  * a missing score is ABSENT, never zero -- zero sorts as harmless
  * a network failure degrades the report, never the run
  * enrichment never influences the security verdict
  * nothing is ever fabricated

Every test here is a way of trying to make the module lie, and checking it does
not.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.core.prioritization import (  # noqa: E402
    EPSS_AVAILABLE,
    EPSS_DISABLED,
    EPSS_NOT_APPLICABLE,
    EPSS_UNAVAILABLE,
    KEV_AVAILABLE,
    KEV_DISABLED,
    KEV_UNAVAILABLE,
    enrich_findings,
    epss_band,
    exploitability_rank,
    extract_cves,
    load_epss,
    load_kev,
)
from framework.core.schema import Finding  # noqa: E402

CVE_A = "CVE-2021-44228"   # log4shell, KEV-listed in reality
CVE_B = "CVE-2019-11043"
CVE_C = "CVE-2024-99999"   # deliberately unscored


def _epss_file(entries):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump({"status": "OK", "data": entries}, handle)
    handle.close()
    return handle.name


def _kev_file(cves):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump({
        "vulnerabilities": [
            {"cveID": cve, "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
             "vendorProject": "Apache", "product": "Log4j",
             "knownRansomwareCampaignUse": "Known"}
            for cve in cves
        ]
    }, handle)
    handle.close()
    return handle.name


def _finding(**kwargs):
    kwargs.setdefault("tool", "trivy")
    kwargs.setdefault("category", "dependency_vulnerability")
    kwargs.setdefault("severity", "HIGH")
    return Finding(**kwargs)


class CveExtraction(unittest.TestCase):
    def test_finds_cve_in_any_field(self):
        self.assertEqual(extract_cves("CVE-2021-44228"), [CVE_A])
        self.assertEqual(extract_cves("fixed in 2.17 (cve-2021-44228)"), [CVE_A])

    def test_deduplicates_and_preserves_order(self):
        self.assertEqual(
            extract_cves("CVE-2019-11043 and CVE-2021-44228 and CVE-2019-11043"),
            [CVE_B, CVE_A],
        )

    def test_reads_lists_and_tuples(self):
        self.assertEqual(extract_cves(["CVE-2021-44228", "unrelated"]), [CVE_A])

    def test_ignores_non_cve_text(self):
        self.assertEqual(extract_cves("CWE-79", "SQL injection", None, 42), [])

    def test_tolerates_none_and_numbers(self):
        self.assertEqual(extract_cves(None, 0, ""), [])


class Bands(unittest.TestCase):
    def test_unknown_score_is_not_established_not_low(self):
        # The whole point: no data must not render as "low risk".
        self.assertEqual(epss_band(None), "NOT_ESTABLISHED")

    def test_bands_are_ordered(self):
        self.assertEqual(epss_band(0.9), "high")
        self.assertEqual(epss_band(0.2), "elevated")
        self.assertEqual(epss_band(0.05), "moderate")
        self.assertEqual(epss_band(0.001), "low")


class OfflineSources(unittest.TestCase):
    """Air-gapped runners must be able to enrich from local files."""

    def test_epss_loads_from_a_local_file(self):
        path = _epss_file([{"cve": CVE_A, "epss": "0.97", "percentile": "0.999", "date": "2026-08-24"}])
        try:
            scores, status, reason, source = load_epss([CVE_A], offline_path=path)
        finally:
            os.unlink(path)
        self.assertEqual(status, EPSS_AVAILABLE)
        self.assertAlmostEqual(scores[CVE_A]["score"], 0.97)
        self.assertIn("local file", source)

    def test_unreadable_epss_file_is_unavailable_not_empty_success(self):
        scores, status, reason, _ = load_epss([CVE_A], offline_path="/nonexistent/epss.json")
        self.assertEqual(status, EPSS_UNAVAILABLE)
        self.assertEqual(scores, {})
        self.assertIn("unreadable", reason)

    def test_kev_loads_from_a_local_file(self):
        path = _kev_file([CVE_A])
        try:
            entries, status, _, _ = load_kev(offline_path=path)
        finally:
            os.unlink(path)
        self.assertEqual(status, KEV_AVAILABLE)
        self.assertEqual(entries[CVE_A]["date_added"], "2021-12-10")

    def test_unreadable_kev_file_is_unavailable(self):
        entries, status, reason, _ = load_kev(offline_path="/nonexistent/kev.json")
        self.assertEqual(status, KEV_UNAVAILABLE)
        self.assertEqual(entries, {})

    def test_malformed_epss_entries_are_skipped_not_defaulted(self):
        path = _epss_file([
            {"cve": CVE_A, "epss": "not-a-number"},
            {"cve": CVE_B, "epss": "0.5", "percentile": "bad"},
        ])
        try:
            scores, status, _, _ = load_epss([CVE_A, CVE_B], offline_path=path)
        finally:
            os.unlink(path)
        self.assertEqual(status, EPSS_AVAILABLE)
        self.assertNotIn(CVE_A, scores, "an unparsable score must not become a score")
        self.assertAlmostEqual(scores[CVE_B]["score"], 0.5)
        self.assertIsNone(scores[CVE_B]["percentile"])


class Enrichment(unittest.TestCase):
    def setUp(self):
        self.epss = _epss_file([
            {"cve": CVE_A, "epss": "0.97", "percentile": "0.999", "date": "2026-08-24"},
            {"cve": CVE_B, "epss": "0.04", "percentile": "0.5", "date": "2026-08-24"},
        ])
        self.kev = _kev_file([CVE_A])

    def tearDown(self):
        for path in (self.epss, self.kev):
            try:
                os.unlink(path)
            except OSError:
                pass

    def _enrich(self, findings, **kwargs):
        kwargs.setdefault("epss_file", self.epss)
        kwargs.setdefault("kev_file", self.kev)
        return enrich_findings(findings, **kwargs)

    def test_scores_and_kev_are_attached(self):
        finding = _finding(description="log4j RCE %s" % CVE_A)
        outcome = self._enrich([finding])
        self.assertEqual(outcome.epss_status, EPSS_AVAILABLE)
        self.assertEqual(outcome.kev_status, KEV_AVAILABLE)
        self.assertAlmostEqual(finding.epss_score, 0.97)
        self.assertTrue(finding.kev_listed)
        self.assertEqual(finding.kev_date_added, "2021-12-10")
        self.assertEqual(finding.epss_band, "high")

    def test_unscored_cve_gets_no_score_rather_than_zero(self):
        finding = _finding(description="something %s" % CVE_C)
        self._enrich([finding])
        self.assertIsNone(
            finding.epss_score,
            "an unscored CVE must stay unscored -- 0.0 would sort it as harmless",
        )
        self.assertFalse(finding.kev_listed)

    def test_finding_with_several_cves_takes_the_worst(self):
        finding = _finding(description="%s and %s" % (CVE_B, CVE_A))
        self._enrich([finding])
        self.assertAlmostEqual(finding.epss_score, 0.97)

    def test_findings_without_cves_are_untouched(self):
        finding = _finding(category="sast_finding", description="SQL injection in login")
        outcome = self._enrich([finding])
        self.assertIsNone(finding.epss_score)
        self.assertEqual(outcome.cves_seen, 0)
        self.assertEqual(outcome.epss_status, EPSS_NOT_APPLICABLE)

    def test_disabled_enrichment_reports_disabled_not_unavailable(self):
        finding = _finding(description=CVE_A)
        outcome = enrich_findings([finding], enable_epss=False, enable_kev=False)
        self.assertEqual(outcome.epss_status, EPSS_DISABLED)
        self.assertEqual(outcome.kev_status, KEV_DISABLED)
        self.assertIsNone(finding.epss_score)

    def test_unavailable_source_degrades_the_report_not_the_run(self):
        finding = _finding(description=CVE_A)
        outcome = enrich_findings(
            [finding], epss_file="/nonexistent/a.json", kev_file="/nonexistent/b.json"
        )
        self.assertEqual(outcome.epss_status, EPSS_UNAVAILABLE)
        self.assertEqual(outcome.kev_status, KEV_UNAVAILABLE)
        self.assertIsNone(finding.epss_score)
        # The finding survives intact -- enrichment loss is never finding loss.
        self.assertEqual(finding.description, CVE_A)

    def test_statement_distinguishes_unavailable_from_no_matches(self):
        unavailable = enrich_findings(
            [_finding(description=CVE_A)], epss_file="/nope.json", kev_file="/nope.json"
        ).statement()
        self.assertIn("NOT available", unavailable)

        matched = self._enrich([_finding(description=CVE_B)]).statement()
        self.assertIn("retrieved", matched)

    def test_counts_are_reported(self):
        outcome = self._enrich([
            _finding(description=CVE_A), _finding(description=CVE_B), _finding(description=CVE_C)
        ])
        self.assertEqual(outcome.cves_seen, 3)
        self.assertEqual(outcome.cves_scored, 2)
        self.assertEqual(outcome.kev_matches, 1)

    def test_result_serialises_for_the_report(self):
        payload = self._enrich([_finding(description=CVE_A)]).to_dict()
        for key in ("epss_status", "kev_status", "cves_seen", "statement"):
            self.assertIn(key, payload)


class Ordering(unittest.TestCase):
    def test_known_exploited_sorts_first(self):
        kev = _finding(severity="MEDIUM")
        kev.kev_listed = True
        critical = _finding(severity="CRITICAL")
        ordered = sorted([critical, kev], key=exploitability_rank)
        self.assertIs(ordered[0], kev, "a known-exploited finding outranks an unexploited critical")

    def test_unscored_sorts_after_scored_at_equal_severity(self):
        scored = _finding(severity="HIGH")
        scored.epss_score = 0.5
        unscored = _finding(severity="HIGH")
        ordered = sorted([unscored, scored], key=exploitability_rank)
        self.assertIs(ordered[0], scored)

    def test_higher_epss_sorts_first(self):
        low, high = _finding(severity="HIGH"), _finding(severity="HIGH")
        low.epss_score, high.epss_score = 0.01, 0.9
        self.assertIs(sorted([low, high], key=exploitability_rank)[0], high)

    def test_severity_still_dominates_within_the_same_kev_state(self):
        info, critical = _finding(severity="INFO"), _finding(severity="CRITICAL")
        self.assertIs(sorted([info, critical], key=exploitability_rank)[0], critical)


class VerdictIndependence(unittest.TestCase):
    """Enrichment orders findings. It must never decide them."""

    def test_enrichment_does_not_change_finding_status_or_severity(self):
        finding = _finding(severity="LOW", description=CVE_A)
        before = (finding.severity, finding.status, finding.fingerprint)
        path_e, path_k = _epss_file([{"cve": CVE_A, "epss": "0.99"}]), _kev_file([CVE_A])
        try:
            enrich_findings([finding], epss_file=path_e, kev_file=path_k)
        finally:
            os.unlink(path_e)
            os.unlink(path_k)
        self.assertTrue(finding.kev_listed)
        self.assertEqual((finding.severity, finding.status, finding.fingerprint), before)


if __name__ == "__main__":
    unittest.main()
