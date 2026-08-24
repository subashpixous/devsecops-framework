"""Invariants for the two machine-readable outputs.

SARIF and CSV exist for the same reason: a finding a developer never sees is a
finding nobody fixes. That makes their integrity requirements different from the
narrative reports.

  * CSV must never truncate. It is the artifact the narrative reports point at
    when they DO truncate, so a limit here would mean no complete list exists
    anywhere a person actually opens.
  * SARIF must never drop a finding. Code scanning shows what is in the file and
    nothing else, so a finding omitted for lack of a line number is invisible.
  * SARIF must carry the framework's fingerprint, or every reformat re-raises
    every finding as new and the alert list becomes noise.
  * A suppression may only reflect a live exception. An EXPIRED one must NOT
    suppress -- expiry exists precisely to force the decision back into view.
"""

import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.report.csv_writer import COLUMNS, build_rows, write_csv  # noqa: E402
from framework.report.sarif_writer import build_sarif, write_sarif  # noqa: E402


def finding(**overrides):
    base = {
        "fingerprint": "fp-1", "tool": "semgrep", "category": "sast_finding",
        "severity": "HIGH", "cwe": "CWE-89", "owasp": "A03:2021-Injection",
        "file": "app/user.php", "line": 42, "endpoint": "", "evidence": "e",
        "description": "SQL injection in the user lookup", "impact": "i",
        "remediation": "Use a prepared statement", "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-01T00:00:00Z", "status": "OPEN", "environment": "prod",
        "commit": "deadbeef", "branch": "main", "rule": "php.sqli",
        "scanner_category": "sast_semgrep", "lifecycle": "NEW",
        "exception_reason": "", "exception_expires": "", "exception_owner": "",
    }
    base.update(overrides)
    return base


def report(items, coverage_complete=True, file_coverage=None):
    return {
        "framework": {"name": "f", "version": "9.9.9", "active_phase": 7},
        "status": {"coverage_complete": coverage_complete},
        "file_coverage": file_coverage or {"available": True, "complete": True},
        "findings": {"total": len(items), "open": len(items), "items": items},
    }


class SarifStructureTestCase(unittest.TestCase):
    def test_every_finding_becomes_a_result(self):
        log = build_sarif(report([finding(), finding(fingerprint="fp-2", file="app/b.php")]))
        self.assertEqual(len(log["runs"][0]["results"]), 2)

    def test_a_finding_with_no_file_is_still_emitted(self):
        log = build_sarif(report([finding(file="", line=0)]))
        results = log["runs"][0]["results"]
        self.assertEqual(len(results), 1, "a finding must never vanish for lack of a location")
        region = results[0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_line_zero_becomes_line_one(self):
        # SARIF regions are 1-based; a literal 0 is rejected by consumers.
        log = build_sarif(report([finding(line=0)]))
        region = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_paths_are_repository_relative_posix(self):
        log = build_sarif(report([finding(file="./app\\sub\\user.php")]))
        uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "app/sub/user.php")

    def test_fingerprint_is_carried_so_alerts_survive_a_reformat(self):
        log = build_sarif(report([finding(fingerprint="stable-1")]))
        prints = log["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(prints["devsecopsFrameworkFingerprint/v1"], "stable-1")

    def test_rule_ids_are_namespaced_by_tool(self):
        log = build_sarif(report([
            finding(tool="semgrep", rule="sqli"),
            finding(tool="sonarqube", rule="sqli", fingerprint="fp-2"),
        ]))
        ids = {r["ruleId"] for r in log["runs"][0]["results"]}
        self.assertEqual(ids, {"semgrep/sqli", "sonarqube/sqli"})
        self.assertEqual(len(log["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_remediation_reaches_the_developer(self):
        log = build_sarif(report([finding()]))
        message = log["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("Use a prepared statement", message)
        self.assertIn("Remediation:", message)


class SarifSeverityTestCase(unittest.TestCase):
    def test_critical_and_high_are_errors(self):
        for severity in ("CRITICAL", "HIGH"):
            log = build_sarif(report([finding(severity=severity)]))
            self.assertEqual(log["runs"][0]["results"][0]["level"], "error")

    def test_unknown_is_not_quietly_downgraded_to_a_note(self):
        # The policy fails UNKNOWN closed at zero. Emitting it as a note would
        # contradict the verdict the same run produced.
        log = build_sarif(report([finding(severity="UNKNOWN")]))
        self.assertEqual(log["runs"][0]["results"][0]["level"], "warning")

    def test_security_severity_is_set_for_the_security_tab(self):
        log = build_sarif(report([finding(severity="CRITICAL")]))
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "9.5")


class SarifSuppressionTestCase(unittest.TestCase):
    def test_accepted_risk_is_suppressed(self):
        log = build_sarif(report([finding(lifecycle="ACCEPTED_RISK",
                                          exception_reason="signed off",
                                          exception_expires="2027-01-01")]))
        suppressions = log["runs"][0]["results"][0]["suppressions"]
        self.assertEqual(suppressions[0]["status"], "accepted")
        self.assertIn("signed off", suppressions[0]["justification"])

    def test_false_positive_is_suppressed(self):
        log = build_sarif(report([finding(lifecycle="FALSE_POSITIVE")]))
        self.assertIn("suppressions", log["runs"][0]["results"][0])

    def test_an_expired_exception_does_not_suppress(self):
        log = build_sarif(report([finding(lifecycle="EXPIRED",
                                          exception_reason="was signed off",
                                          exception_expires="2020-01-01")]))
        self.assertNotIn(
            "suppressions", log["runs"][0]["results"][0],
            "an expired exception must return the finding to view, not hide it",
        )

    def test_a_new_finding_is_never_suppressed(self):
        log = build_sarif(report([finding(lifecycle="NEW")]))
        self.assertNotIn("suppressions", log["runs"][0]["results"][0])


class SarifCoverageWarningTestCase(unittest.TestCase):
    def test_incomplete_category_coverage_is_announced_in_the_file(self):
        log = build_sarif(report([finding()], coverage_complete=False))
        notifications = log["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        text = " ".join(n["message"]["text"] for n in notifications)
        self.assertIn("INCOMPLETE", text)
        self.assertIn("not evidence of absence", text)

    def test_unanalysed_files_are_announced_in_the_file(self):
        log = build_sarif(report([finding()], file_coverage={
            "available": True, "complete": False,
            "statement": "3 of 10 code files were NOT read by any scanner in this run.",
        }))
        notifications = log["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        text = " ".join(n["message"]["text"] for n in notifications)
        self.assertIn("NOT read by any scanner", text)

    def test_a_complete_run_adds_no_warning(self):
        log = build_sarif(report([finding()]))
        self.assertNotIn("toolExecutionNotifications", log["runs"][0]["invocations"][0])


class SarifSerialisationTestCase(unittest.TestCase):
    def test_written_file_is_valid_json_with_the_expected_version(self):
        directory = tempfile.mkdtemp(prefix="sarif-test-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = write_sarif(report([finding()]), directory)
        with open(path, encoding="utf-8") as handle:
            log = json.load(handle)
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["runs"][0]["tool"]["driver"]["semanticVersion"], "9.9.9")

    def test_an_empty_finding_list_produces_a_valid_empty_run(self):
        log = build_sarif(report([]))
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["runs"][0]["tool"]["driver"]["rules"], [])


class CsvCompletenessTestCase(unittest.TestCase):
    """The one output that is never allowed to summarise."""

    def test_every_finding_is_written_however_many_there_are(self):
        items = [finding(fingerprint="fp-%d" % i, file="app/f%d.php" % i) for i in range(500)]
        rows = build_rows(report(items))
        self.assertEqual(len(rows), 500)

    def test_written_file_round_trips_with_every_row(self):
        directory = tempfile.mkdtemp(prefix="csv-test-")
        self.addCleanup(shutil.rmtree, directory, True)
        items = [finding(fingerprint="fp-%d" % i) for i in range(120)]
        path = write_csv(report(items), directory)
        with open(path, encoding="utf-8-sig", newline="") as handle:
            parsed = list(csv.DictReader(handle))
        self.assertEqual(len(parsed), 120)
        self.assertEqual(set(parsed[0]), set(COLUMNS))


class CsvIntegrityTestCase(unittest.TestCase):
    def test_a_description_containing_commas_and_quotes_cannot_shift_columns(self):
        nasty = 'Injection in "user", id, param; see report'
        rows = build_rows(report([finding(description=nasty)]))
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(COLUMNS))
        writer.writeheader()
        writer.writerow(rows[0])
        buffer.seek(0)
        parsed = list(csv.DictReader(buffer))[0]
        self.assertEqual(parsed["description"], nasty)
        self.assertEqual(parsed["file"], "app/user.php")

    def test_newlines_are_flattened_so_spreadsheets_do_not_break_rows(self):
        rows = build_rows(report([finding(remediation="line one\nline two\r\nline three")]))
        self.assertNotIn("\n", rows[0]["remediation"])
        self.assertIn("line one line two line three", rows[0]["remediation"])

    def test_list_fields_are_joined_not_stringified_as_python(self):
        rows = build_rows(report([finding(tags=["a", "b"])]))
        # `tags` is not a column, but the same flattening applies to any list.
        self.assertNotIn("['a'", " ".join(rows[0].values()))


class CsvTriageOrderTestCase(unittest.TestCase):
    def test_most_severe_first(self):
        rows = build_rows(report([
            finding(severity="LOW", fingerprint="l"),
            finding(severity="CRITICAL", fingerprint="c"),
            finding(severity="MEDIUM", fingerprint="m"),
        ]))
        self.assertEqual([r["severity"] for r in rows], ["CRITICAL", "MEDIUM", "LOW"])

    def test_unknown_sorts_above_medium_because_the_policy_fails_it_closed(self):
        rows = build_rows(report([
            finding(severity="MEDIUM", fingerprint="m"),
            finding(severity="UNKNOWN", fingerprint="u"),
        ]))
        self.assertEqual([r["severity"] for r in rows], ["UNKNOWN", "MEDIUM"])

    def test_new_findings_come_first_within_a_severity(self):
        rows = build_rows(report([
            finding(lifecycle="EXISTING", fingerprint="e"),
            finding(lifecycle="NEW", fingerprint="n"),
        ]))
        self.assertEqual([r["lifecycle"] for r in rows], ["NEW", "EXISTING"])

    def test_the_owner_columns_are_present_and_empty_for_a_human_to_fill(self):
        rows = build_rows(report([finding()]))
        for column in ("owner", "target_date", "notes"):
            self.assertIn(column, rows[0])
            self.assertEqual(rows[0][column], "")


if __name__ == "__main__":
    unittest.main()
