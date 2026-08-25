"""Evidence manifest contract tests.

The manifest is what turns a report from an assertion into a record. These tests
hold it to the same standard as the rest of the framework: it must never claim
more than it can prove, and it must never take down the run it documents.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.collectors.base import ScannerResult  # noqa: E402
from framework.core.evidence import (  # noqa: E402
    MANIFEST_FILENAME,
    build_manifest,
    sha256_file,
    write_manifest,
)


def _report(**overrides):
    report = {
        "framework": {"name": "F", "version": "0.5.0", "active_phase": 7},
        "project": {"repository": "org/app", "commit": "abc123", "branch": "main",
                    "project_name": "app", "environment": "production"},
        "policy": {"name": "default", "schema_version": 1, "active_phase": 7,
                   "required_categories": ["sast_semgrep"],
                   "severity_thresholds": {"CRITICAL": 0},
                   "source_paths": ["default-policy.yml"]},
        "status": {"build": "PASS", "deployment": "DEPLOYED", "security": "NOT_VERIFIED",
                   "runtime_security": "NOT_TESTED", "verdict_scope": "PHASE_7",
                   "coverage_complete": False},
        "quality_gate": {"status": "OK", "analysis_state": "SONARQUBE_SCAN_COMPLETED",
                         "project_key": "app", "analysis_date": "2026-08-24T09:00:00+0000",
                         "analysis_revision": "abc123", "scanned_commit": "abc123",
                         "freshness_basis": "revision"},
        "file_coverage": {"available": True, "code_files": 149, "code_files_analysed": 107,
                          "code_files_not_analysed": 42, "coverage_percent": 71.8,
                          "complete": False, "scanners_unavailable": ["gitleaks"],
                          "scanners_failed": [], "statement": "42 of 149 not read."},
        "findings": {"open": 12},
        "limitations": [{"code": "SAST_LANGUAGE_COVERAGE_UNCONFIRMED"}],
        "manual_controls": [{"key": "idor_bola", "title": "IDOR / BOLA"}],
    }
    report.update(overrides)
    return report


def _ok_result(tool="semgrep"):
    result = ScannerResult(tool=tool, category_key="sast_semgrep")
    result.metadata["version"] = "1.2.3"
    result.metadata["tool_run"] = {"returncode": 0, "argv": ["semgrep", "scan"], "duration": 4.2}
    result.payload = {}
    result.succeed()
    return result.finish()


def _failed_result(tool="gitleaks"):
    result = ScannerResult(tool=tool, category_key="secret_scanning")
    result.fail("gitleaks is not installed or not on PATH.")
    return result.finish()


class Provenance(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_records_what_was_validated(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertTrue(manifest["available"])
        self.assertEqual(manifest["subject"]["commit"], "abc123")
        self.assertEqual(manifest["subject"]["repository"], "org/app")

    def test_records_the_tooling_that_produced_the_verdict(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertEqual(manifest["tooling"]["framework_version"], "0.5.0")
        self.assertTrue(manifest["tooling"]["python_version"])
        self.assertTrue(manifest["tooling"]["platform"])

    def test_records_the_rules_the_verdict_was_judged_against(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertEqual(manifest["policy"]["required_categories"], ["sast_semgrep"])
        self.assertEqual(manifest["policy"]["severity_thresholds"], {"CRITICAL": 0})

    def test_records_the_external_analysis_identity(self):
        manifest = build_manifest(_report(), [], self.dir)
        sonar = manifest["external_analysis"]["sonarqube"]
        self.assertEqual(sonar["state"], "SONARQUBE_SCAN_COMPLETED")
        self.assertEqual(sonar["analysis_revision"], "abc123")
        self.assertEqual(sonar["freshness_basis"], "revision")


class ExecutionRecord(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_distinguishes_completed_from_not_completed(self):
        manifest = build_manifest(_report(), [_ok_result(), _failed_result()], self.dir)
        execution = manifest["execution"]
        self.assertEqual(execution["scanners_registered"], 2)
        self.assertEqual(execution["scanners_completed"], 1)
        self.assertEqual(execution["scanners_not_completed"], 1)

    def test_records_exit_code_and_command(self):
        manifest = build_manifest(_report(), [_ok_result()], self.dir)
        record = manifest["execution"]["scanner_records"][0]
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["command"], ["semgrep", "scan"])
        self.assertEqual(record["version"], "1.2.3")

    def test_a_scanner_that_never_ran_has_no_fabricated_exit_code(self):
        manifest = build_manifest(_report(), [_failed_result()], self.dir)
        record = manifest["execution"]["scanner_records"][0]
        self.assertEqual(record["exit_code"], "NOT_ESTABLISHED")
        self.assertFalse(record["trustworthy"])
        self.assertTrue(record["errors"])


class Limits(unittest.TestCase):
    """The manifest must state what it did NOT establish."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_limitations_are_carried_verbatim(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertEqual(manifest["limitations"], [{"code": "SAST_LANGUAGE_COVERAGE_UNCONFIRMED"}])

    def test_untested_manual_controls_are_named(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertIn("IDOR / BOLA", manifest["manual_controls_not_tested"])

    def test_unavailable_scanners_are_carried_into_coverage(self):
        manifest = build_manifest(_report(), [], self.dir)
        self.assertEqual(manifest["coverage"]["scanners_unavailable"], ["gitleaks"])
        self.assertFalse(manifest["coverage"]["complete"])

    def test_integrity_note_does_not_overclaim(self):
        manifest = build_manifest(_report(), [], self.dir)
        note = manifest["integrity_note"]
        self.assertIn("NOT signatures", note)
        self.assertIn("authenticity", note)


class Integrity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "report.md"), "w", encoding="utf-8") as handle:
            handle.write("# report\n")
        with open(os.path.join(self.dir, "findings.csv"), "w", encoding="utf-8") as handle:
            handle.write("severity\n")

    def test_every_artefact_is_hashed(self):
        manifest = build_manifest(_report(), [], self.dir)
        names = {a["file"] for a in manifest["artefacts"]}
        self.assertEqual(names, {"report.md", "findings.csv"})
        for artefact in manifest["artefacts"]:
            self.assertEqual(len(artefact["sha256"]), 64)

    def test_hash_changes_when_content_changes(self):
        before = build_manifest(_report(), [], self.dir)["artefacts"]
        with open(os.path.join(self.dir, "report.md"), "a", encoding="utf-8") as handle:
            handle.write("tampered\n")
        after = build_manifest(_report(), [], self.dir)["artefacts"]
        pick = lambda rows: [a["sha256"] for a in rows if a["file"] == "report.md"][0]  # noqa: E731
        self.assertNotEqual(pick(before), pick(after))

    def test_unreadable_file_is_marked_not_silently_skipped(self):
        self.assertTrue(sha256_file(os.path.join(self.dir, "nope.bin")).startswith("UNREADABLE"))

    def test_manifest_excludes_itself(self):
        write_manifest(build_manifest(_report(), [], self.dir), self.dir)
        manifest = build_manifest(_report(), [], self.dir)
        self.assertNotIn(MANIFEST_FILENAME, {a["file"] for a in manifest["artefacts"]})

    def test_manifest_is_written_and_reloadable(self):
        path = write_manifest(build_manifest(_report(), [], self.dir), self.dir)
        with open(path, encoding="utf-8") as handle:
            self.assertTrue(json.load(handle)["available"])


class NeverBreaksTheRun(unittest.TestCase):
    def test_a_manifest_that_cannot_be_built_reports_unavailable(self):
        manifest = build_manifest(None, [], None)  # type: ignore[arg-type]
        self.assertFalse(manifest["available"])
        self.assertIn("could not be assembled", manifest["reason"])
        self.assertIn("NOT_ESTABLISHED", manifest["warning"])

    def test_a_missing_output_directory_is_survivable(self):
        manifest = build_manifest(_report(), [], os.path.join(tempfile.gettempdir(), "nope-xyz"))
        self.assertTrue(manifest["available"])
        self.assertEqual(manifest["artefacts"], [])


if __name__ == "__main__":
    unittest.main()
