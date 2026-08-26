"""SonarQube collector contract tests.

SonarQube is the only scanner this framework does not execute. It reads results
produced by someone else's analysis, at some other time, over some other
revision. Every other collector knows what it scanned because it did the
scanning; this one has to prove it.

These tests cover the proof:

  * analysis identity   -- date and revision are read and reported
  * freshness           -- a revision mismatch or an aged-out analysis is STALE
  * permission failure  -- 401/403 is reported as an authorisation problem
  * unavailability      -- a missing host, token, key or server is never a PASS
  * state exclusivity   -- exactly one of the four states, and only
                           SONARQUBE_SCAN_COMPLETED leaves the result trustworthy

The whole point is negative: none of these conditions may produce a result the
status engine can turn into PASS.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.collectors.sonarqube import (  # noqa: E402
    DEFAULT_MAX_ANALYSIS_AGE_DAYS,
    SONARQUBE_PERMISSION_ERROR,
    SONARQUBE_RESULT_STALE,
    SONARQUBE_RESULT_UNAVAILABLE,
    SONARQUBE_SCAN_COMPLETED,
    SonarQubeCollector,
    evaluate_freshness,
    parse_sonar_datetime,
    redact_host,
)

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
COMMIT = "3d108dfa1b2c3d4e5f60718293a4b5c6d7e8f900"


def _iso(when):
    """SonarQube's own timestamp format: offset with no colon."""
    return when.strftime("%Y-%m-%dT%H:%M:%S+0000")


class FakeServer:
    """Minimal stand-in for the SonarQube Web API.

    Stubs the collector's single network primitive, so every endpoint, the
    branch fallback and the pager all route through it exactly as in production.
    """

    def __init__(self, analyses=None, status_by_path=None, gate_status="OK",
                 issues=None, hotspots=None, measures=None):
        self.analyses = analyses if analyses is not None else [
            {"key": "AY_1", "date": _iso(NOW - timedelta(hours=2)),
             "revision": COMMIT, "projectVersion": "1.4.0"}
        ]
        self.status_by_path = status_by_path or {}
        self.gate_status = gate_status
        self.issues = issues or []
        self.hotspots = hotspots or []
        self.measures = measures if measures is not None else [
            {"metric": "coverage", "value": "72.4"},
            {"metric": "ncloc", "value": "18422"},
            {"metric": "vulnerabilities", "value": "3"},
        ]
        self.calls = []

    def get(self, path, params=None):
        self.calls.append(path)
        forced = self.status_by_path.get(path)
        if forced:
            return None, "HTTP %d from %s" % (forced, path), forced
        if path == "/api/server/version":
            return {"version": "10.6"}, None, 200
        if path == "/api/project_analyses/search":
            return {"analyses": self.analyses,
                    "paging": {"total": len(self.analyses), "pageSize": 1}}, None, 200
        if path == "/api/qualitygates/project_status":
            return {"projectStatus": {"status": self.gate_status, "conditions": []}}, None, 200
        if path == "/api/measures/component":
            return {"component": {"measures": self.measures}}, None, 200
        if path == "/api/issues/search":
            return {"issues": self.issues,
                    "paging": {"total": len(self.issues), "pageSize": 500}}, None, 200
        if path == "/api/hotspots/search":
            return {"hotspots": self.hotspots,
                    "paging": {"total": len(self.hotspots), "pageSize": 500}}, None, 200
        if path == "/api/rules/show":
            return {"rule": {"securityStandards": [], "name": "r", "type": "VULNERABILITY"}}, None, 200
        return None, "unexpected path %s" % path, 404


def _collector(server, **kwargs):
    kwargs.setdefault("host_url", "https://sonar.example.com")
    kwargs.setdefault("token", "t0ken")
    kwargs.setdefault("project_key", "demo-project")
    kwargs.setdefault("commit", COMMIT)
    kwargs.setdefault("enrich_rules", False)
    collector = SonarQubeCollector(**kwargs)
    collector._get = server.get  # noqa: SLF001 - the documented seam for these tests
    return collector


# --- Timestamp parsing -------------------------------------------------------


class ParseSonarDatetime(unittest.TestCase):
    def test_parses_sonarqube_offset_without_colon(self):
        parsed = parse_sonar_datetime("2026-08-24T09:12:33+0000")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2026)
        self.assertIsNotNone(parsed.tzinfo)

    def test_parses_zulu_form(self):
        self.assertIsNotNone(parse_sonar_datetime("2026-08-24T09:12:33Z"))

    def test_naive_timestamp_is_treated_as_utc(self):
        parsed = parse_sonar_datetime("2026-08-24T09:12:33")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_unparsable_returns_none_not_now(self):
        # An unreadable date must never be optimistically treated as recent.
        for value in ("", "   ", "not-a-date", "24/08/2026"):
            self.assertIsNone(parse_sonar_datetime(value), value)


# --- Freshness ---------------------------------------------------------------


class Freshness(unittest.TestCase):
    def test_matching_revision_is_fresh_at_any_age(self):
        ancient = NOW - timedelta(days=900)
        fresh, basis, reason = evaluate_freshness(ancient, COMMIT, COMMIT, now=NOW)
        self.assertTrue(fresh)
        self.assertEqual(basis, "revision")
        self.assertIn("commit under validation", reason)

    def test_mismatched_revision_is_stale_however_recent(self):
        fresh, basis, reason = evaluate_freshness(
            NOW - timedelta(minutes=1), "aaaaaaaaaaaa1111", COMMIT, now=NOW
        )
        self.assertFalse(fresh)
        self.assertEqual(basis, "revision")
        self.assertIn("different code", reason)

    def test_short_revision_prefix_still_matches(self):
        fresh, _, _ = evaluate_freshness(NOW, COMMIT[:8], COMMIT, now=NOW)
        self.assertTrue(fresh)

    def test_missing_date_and_revision_is_not_fresh(self):
        fresh, basis, _ = evaluate_freshness(None, "", "", now=NOW)
        self.assertFalse(fresh)
        self.assertEqual(basis, "unknown")

    def test_recent_analysis_without_revision_is_fresh_by_age_only(self):
        fresh, basis, reason = evaluate_freshness(NOW - timedelta(days=1), "", "", now=NOW)
        self.assertTrue(fresh)
        self.assertEqual(basis, "age")
        # The report must not present an age check as proof of revision identity.
        self.assertIn("age-based assurance only", reason)

    def test_aged_out_analysis_is_stale(self):
        old = NOW - timedelta(days=DEFAULT_MAX_ANALYSIS_AGE_DAYS + 1)
        fresh, basis, reason = evaluate_freshness(old, "", "", now=NOW)
        self.assertFalse(fresh)
        self.assertEqual(basis, "age")
        self.assertIn("day(s) old", reason)

    def test_future_dated_analysis_is_not_trusted(self):
        fresh, _, reason = evaluate_freshness(NOW + timedelta(days=2), "", "", now=NOW)
        self.assertFalse(fresh)
        self.assertIn("future", reason)

    def test_custom_age_window_is_honoured(self):
        two_days = NOW - timedelta(days=2)
        self.assertFalse(evaluate_freshness(two_days, "", "", max_age_days=1, now=NOW)[0])
        self.assertTrue(evaluate_freshness(two_days, "", "", max_age_days=30, now=NOW)[0])


# --- Collector states --------------------------------------------------------


class AnalysisStates(unittest.TestCase):
    def test_current_analysis_completes_and_is_trustworthy(self):
        result = _collector(FakeServer()).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_SCAN_COMPLETED)
        self.assertTrue(result.is_trustworthy)
        self.assertEqual(result.payload["freshness"]["basis"], "revision")

    def test_revision_mismatch_is_stale_and_not_trustworthy(self):
        server = FakeServer(analyses=[
            {"key": "AY_0", "date": _iso(NOW - timedelta(hours=1)),
             "revision": "ffffffffffffffffffffffffffffffffffffffff"}
        ])
        result = _collector(server).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_STALE)
        self.assertFalse(
            result.is_trustworthy,
            "a stale analysis must never be trustworthy -- the category could reach PASS",
        )
        self.assertTrue(any("SONARQUBE_RESULT_STALE" in w for w in result.warnings))

    def test_aged_out_analysis_is_stale(self):
        server = FakeServer(analyses=[
            {"key": "AY_0", "date": _iso(NOW - timedelta(days=400)), "revision": ""}
        ])
        result = _collector(server, commit="").collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_STALE)
        self.assertFalse(result.is_trustworthy)

    def test_stale_findings_are_still_reported(self):
        """Stale data is real data about other code. It is shown, not deleted."""
        server = FakeServer(
            analyses=[{"key": "A", "date": _iso(NOW), "revision": "0" * 40}],
            issues=[{"key": "i1", "rule": "php:S1", "type": "VULNERABILITY",
                     "severity": "CRITICAL", "message": "m", "component": "c:app.php"}],
        )
        result = _collector(server).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_STALE)
        self.assertEqual(len(result.payload["issues"]), 1)

    def test_permission_denied_is_reported_as_permission_error(self):
        server = FakeServer(status_by_path={"/api/qualitygates/project_status": 403})
        result = _collector(server).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_PERMISSION_ERROR)
        self.assertFalse(result.is_trustworthy)
        self.assertTrue(any("SONARQUBE_PERMISSION_ERROR" in e for e in result.errors))

    def test_unauthorized_is_also_a_permission_error(self):
        server = FakeServer(status_by_path={"/api/issues/search": 401})
        result = _collector(server).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_PERMISSION_ERROR)

    def test_server_error_is_unavailable_not_stale(self):
        server = FakeServer(status_by_path={"/api/qualitygates/project_status": 500})
        result = _collector(server).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_UNAVAILABLE)
        self.assertFalse(result.is_trustworthy)

    def test_project_with_no_analysis_is_not_fresh(self):
        result = _collector(FakeServer(analyses=[])).collect()
        self.assertIn(
            result.metadata["analysis_state"],
            (SONARQUBE_RESULT_STALE, SONARQUBE_RESULT_UNAVAILABLE),
        )
        self.assertFalse(result.is_trustworthy)

    def test_missing_host_is_unavailable(self):
        result = SonarQubeCollector(host_url="", token="t", project_key="k").collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_UNAVAILABLE)
        self.assertFalse(result.is_trustworthy)

    def test_missing_token_is_unavailable(self):
        result = SonarQubeCollector(host_url="https://s", token="", project_key="k").collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_UNAVAILABLE)
        self.assertFalse(result.is_trustworthy)

    def test_unresolvable_project_key_is_unavailable(self):
        result = SonarQubeCollector(
            host_url="https://s", token="t", project_key=None, workspace=os.sep + "nonexistent"
        ).collect()
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_RESULT_UNAVAILABLE)
        self.assertFalse(result.is_trustworthy)

    def test_exactly_one_state_is_recorded(self):
        result = _collector(FakeServer()).collect()
        self.assertEqual(result.metadata["analysis_state"], result.payload["analysis_state"])


# --- Reported identity and measures ------------------------------------------


class ReportedIdentity(unittest.TestCase):
    def test_analysis_identity_reaches_the_payload(self):
        result = _collector(FakeServer()).collect()
        analysis = result.payload["analysis"]
        self.assertTrue(analysis["available"])
        self.assertEqual(analysis["revision"], COMMIT)
        self.assertEqual(analysis["project_version"], "1.4.0")

    def test_scanned_commit_is_recorded_for_the_report(self):
        result = _collector(FakeServer()).collect()
        self.assertEqual(result.metadata["scanned_commit"], COMMIT)

    def test_measures_are_collected(self):
        result = _collector(FakeServer()).collect()
        self.assertEqual(result.payload["measures"]["coverage"], "72.4")
        self.assertEqual(result.payload["measures"]["ncloc"], "18422")

    def test_absent_measures_are_absent_not_zero(self):
        """A project with no coverage metric is not a project with 0% coverage."""
        result = _collector(FakeServer(measures=[])).collect()
        self.assertNotIn("coverage", result.payload["measures"])

    def test_measure_failure_is_a_warning_not_a_failure(self):
        server = FakeServer(status_by_path={"/api/measures/component": 500})
        result = _collector(server).collect()
        self.assertTrue(any("measures" in w for w in result.warnings))
        # Context is nice to have; losing it must not invalidate the scan.
        self.assertEqual(result.metadata["analysis_state"], SONARQUBE_SCAN_COMPLETED)


class CredentialHygiene(unittest.TestCase):
    def test_host_redaction_strips_embedded_credentials(self):
        self.assertEqual(
            redact_host("https://user:secret@sonar.example.com:9000/x"),
            "https://sonar.example.com:9000",
        )

    def test_token_never_appears_in_the_result(self):
        result = _collector(FakeServer(), token="SUPERSECRETTOKEN").collect()
        blob = repr(result.to_dict()) + repr(result.payload)
        self.assertNotIn("SUPERSECRETTOKEN", blob)


if __name__ == "__main__":
    unittest.main()
