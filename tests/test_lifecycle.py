"""Phase 4 finding-lifecycle invariants.

Two rules here are load-bearing for the whole model:

  * An expired suppression must NOT suppress. Otherwise accepted risk rots into
    permanent silent acceptance.
  * A finding is only FIXED when the scanner that found it ran successfully.
    Otherwise a broken scanner looks like remediation.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.core.lifecycle import (  # noqa: E402
    LIFECYCLE_ACCEPTED_RISK,
    LIFECYCLE_EXISTING,
    LIFECYCLE_EXPIRED_EXCEPTION,
    LIFECYCLE_FALSE_POSITIVE,
    LIFECYCLE_NEW,
    Exception_,
    apply_lifecycle,
    is_suppressed,
    load_baseline,
    load_exceptions,
)
from framework.core.schema import Finding  # noqa: E402

FUTURE = (date.today() + timedelta(days=90)).isoformat()
PAST = (date.today() - timedelta(days=1)).isoformat()


def finding(description="Hard-coded credential", tool="semgrep", category="sast_finding",
            scanner_category="sast_semgrep", severity="HIGH", file="src/a.ts"):
    return Finding(
        tool=tool, category=category, severity=severity, file=file, line=10,
        description=description, rule="rule-1", scanner_category=scanner_category, status="OPEN",
    )


def baseline_from(findings):
    return {f.fingerprint: f.to_dict() for f in findings}


class ExceptionExpiryTestCase(unittest.TestCase):
    def test_exception_with_future_date_is_not_expired(self):
        self.assertFalse(Exception_("fp", "accepted_risk", expires=FUTURE).is_expired())

    def test_exception_with_past_date_is_expired(self):
        self.assertTrue(Exception_("fp", "accepted_risk", expires=PAST).is_expired())

    def test_exception_with_no_expiry_is_treated_as_expired(self):
        """An undated suppression has no review point, so it fails closed."""
        self.assertTrue(Exception_("fp", "accepted_risk", expires="").is_expired())

    def test_exception_with_unparsable_date_is_expired(self):
        self.assertTrue(Exception_("fp", "accepted_risk", expires="soon").is_expired())


class LifecycleTestCase(unittest.TestCase):
    def test_without_baseline_everything_is_new_and_nothing_is_fixed(self):
        current = [finding()]
        summary = apply_lifecycle(current, {}, "", {}, "", {"sast_semgrep"})
        self.assertEqual(summary.new, 1)
        self.assertEqual(summary.existing, 0)
        self.assertEqual(summary.fixed, 0)
        self.assertEqual(current[0].lifecycle, LIFECYCLE_NEW)
        self.assertFalse(summary.baseline_available)

    def test_finding_present_in_baseline_is_existing(self):
        previous = finding()
        current = [finding()]
        summary = apply_lifecycle(current, baseline_from([previous]), "base.json", {}, "", {"sast_semgrep"})
        self.assertEqual(current[0].lifecycle, LIFECYCLE_EXISTING)
        self.assertEqual(summary.existing, 1)
        self.assertEqual(summary.new, 0)

    def test_absent_finding_is_fixed_when_its_scanner_succeeded(self):
        previous = finding()
        summary = apply_lifecycle([], baseline_from([previous]), "base.json", {}, "", {"sast_semgrep"})
        self.assertEqual(summary.fixed, 1)
        self.assertEqual(summary.unknown, 0)

    def test_absent_finding_is_UNKNOWN_when_its_scanner_failed(self):
        """A scanner that did not run must never look like remediation."""
        previous = finding()
        summary = apply_lifecycle([], baseline_from([previous]), "base.json", {}, "", set())
        self.assertEqual(summary.fixed, 0)
        self.assertEqual(summary.unknown, 1)
        self.assertTrue(any("not FIXED" in n or "UNKNOWN" in n for n in summary.notes))

    def test_first_seen_is_carried_forward_from_baseline(self):
        previous = finding()
        previous.first_seen = "2020-01-01T00:00:00Z"
        current = [finding()]
        apply_lifecycle(current, baseline_from([previous]), "base.json", {}, "", {"sast_semgrep"})
        self.assertEqual(current[0].first_seen, "2020-01-01T00:00:00Z")


class SuppressionTestCase(unittest.TestCase):
    def test_valid_accepted_risk_suppresses(self):
        current = [finding()]
        exceptions = {current[0].fingerprint: Exception_(current[0].fingerprint, "accepted_risk",
                                                         reason="compensating control", expires=FUTURE)}
        summary = apply_lifecycle(current, {}, "", exceptions, "exc.yml", {"sast_semgrep"})
        self.assertEqual(current[0].lifecycle, LIFECYCLE_ACCEPTED_RISK)
        self.assertTrue(is_suppressed(current[0]))
        self.assertEqual(summary.accepted_risk, 1)

    def test_valid_false_positive_suppresses(self):
        current = [finding()]
        exceptions = {current[0].fingerprint: Exception_(current[0].fingerprint, "false_positive",
                                                         expires=FUTURE)}
        apply_lifecycle(current, {}, "", exceptions, "exc.yml", {"sast_semgrep"})
        self.assertEqual(current[0].lifecycle, LIFECYCLE_FALSE_POSITIVE)
        self.assertTrue(is_suppressed(current[0]))

    def test_EXPIRED_exception_does_NOT_suppress(self):
        """The core Phase 4 invariant."""
        current = [finding()]
        exceptions = {current[0].fingerprint: Exception_(current[0].fingerprint, "accepted_risk",
                                                         expires=PAST)}
        summary = apply_lifecycle(current, {}, "", exceptions, "exc.yml", {"sast_semgrep"})
        self.assertEqual(current[0].lifecycle, LIFECYCLE_EXPIRED_EXCEPTION)
        self.assertFalse(is_suppressed(current[0]))
        self.assertEqual(summary.expired_exceptions, 1)
        self.assertEqual(summary.accepted_risk, 0)

    def test_undated_exception_does_NOT_suppress(self):
        current = [finding()]
        exceptions = {current[0].fingerprint: Exception_(current[0].fingerprint, "accepted_risk")}
        summary = apply_lifecycle(current, {}, "", exceptions, "exc.yml", {"sast_semgrep"})
        self.assertFalse(is_suppressed(current[0]))
        self.assertEqual(summary.expired_exceptions, 1)
        detail = summary.expired_exception_details[0]
        self.assertIn("no expiry", detail["why"])
        self.assertIn("NOT applied", detail["effect"])


class LoaderTestCase(unittest.TestCase):
    def test_missing_baseline_is_recorded_not_silently_ignored(self):
        data, source, notes = load_baseline("/definitely/not/here.json")
        self.assertEqual(data, {})
        self.assertEqual(source, "")
        self.assertTrue(notes)

    def test_no_baseline_path_is_recorded(self):
        _data, _source, notes = load_baseline(None)
        self.assertTrue(any("NEW" in n for n in notes))

    def test_baseline_round_trip(self):
        previous = finding()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"findings": [previous.to_dict()]}, fh)
            path = fh.name
        try:
            data, source, _notes = load_baseline(path)
            self.assertIn(previous.fingerprint, data)
            self.assertTrue(source.endswith(".json"))
        finally:
            os.unlink(path)

    def test_exceptions_round_trip_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"exceptions": [
                {"fingerprint": "abc", "kind": "accepted_risk", "expires": FUTURE, "reason": "r"},
                {"fingerprint": "def", "kind": "bogus_kind"},
                {"kind": "accepted_risk"},
            ]}, fh)
            path = fh.name
        try:
            data, source, notes = load_exceptions(path)
            self.assertIn("abc", data)
            self.assertNotIn("def", data)       # unknown kind rejected
            self.assertEqual(len(data), 1)      # entry without fingerprint rejected
            self.assertTrue(source.endswith(".json"))
            self.assertEqual(len(notes), 2)
        finally:
            os.unlink(path)

    def test_unparsable_exceptions_file_applies_NO_suppressions(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            fh.write("{not json")
            path = fh.name
        try:
            data, _source, notes = load_exceptions(path)
            self.assertEqual(data, {})
            self.assertTrue(any("NO suppressions" in n for n in notes))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
