"""Invariants for the file-level coverage census.

The category model can say "SAST ran". It cannot say "SAST read every file",
and those are different claims. This census makes the second one checkable, so
its own failure modes matter more than usual:

  * a scanner that did NOT complete must be credited with nothing. Crediting it
    would report full coverage produced by a scan that never ran.
  * an absent census must read as UNKNOWN, never as complete.
  * a secret scanner reading a file is not the same as that file having been
    analysed for vulnerabilities, and must not count as such -- otherwise the
    one number that matters is 100% on every run and means nothing.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.collectors.base import ScannerResult  # noqa: E402
from framework.core import scanpaths  # noqa: E402
from framework.core.coverage import (  # noqa: E402
    BUCKET_ANALYSED,
    BUCKET_EXCLUDED,
    BUCKET_NO_ENGINE,
    BUCKET_NOT_CODE,
    BUCKET_SCANNER_FAILED,
    build_manifest,
    scan_coverage_from_results,
)


def declaring_result(tool, intent, languages=("php",), extensions=(".php",), trustworthy=True):
    """A ScannerResult that declares coverage, in the state a real run leaves it."""
    result = ScannerResult(tool=tool, category_key="c_%s" % tool)
    plan = scanpaths.resolve(intent, list(languages))
    result.metadata["coverage"] = {
        "exclusions": plan.to_dict(),
        "extensions": list(extensions),
    }
    if trustworthy:
        result.payload = {}
        result.succeed()
    else:
        result.fail("the tool is not installed")
    return result


class Workspace:
    """Throwaway tree; files are created by relative path."""

    def __init__(self, files):
        self.root = tempfile.mkdtemp(prefix="coverage-test-")
        for relative in files:
            path = os.path.join(self.root, relative.replace("/", os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class CreditOnlyCompletedScannersTestCase(unittest.TestCase):
    """The invariant that keeps this census honest."""

    def setUp(self):
        self.workspace = Workspace(["app/index.php", "app/user.php"])
        self.addCleanup(self.workspace.cleanup)

    def test_a_completed_scanner_covers_the_files_it_reads(self):
        manifest = build_manifest(
            self.workspace.root,
            [declaring_result("semgrep", scanpaths.INTENT_SAST)],
            ["php"],
        )
        self.assertEqual(manifest["code_files_analysed"], 2)
        self.assertTrue(manifest["complete"])

    def test_a_failed_scanner_is_credited_with_nothing(self):
        manifest = build_manifest(
            self.workspace.root,
            [declaring_result("semgrep", scanpaths.INTENT_SAST, trustworthy=False)],
            ["php"],
        )
        self.assertEqual(manifest["code_files_analysed"], 0)
        self.assertEqual(manifest["counts"][BUCKET_SCANNER_FAILED], 2)
        self.assertFalse(manifest["complete"])

    def test_a_partial_scanner_is_credited_with_nothing(self):
        # PARTIAL means the tool itself said its reach was incomplete. Which
        # files it did read is unknown, so no file may be claimed.
        result = declaring_result("semgrep", scanpaths.INTENT_SAST)
        result.partial("rules failed to load")
        manifest = build_manifest(self.workspace.root, [result], ["php"])
        self.assertEqual(manifest["code_files_analysed"], 0)

    def test_no_scanners_at_all_reports_zero_and_says_so(self):
        manifest = build_manifest(self.workspace.root, [], ["php"])
        self.assertEqual(manifest["code_files_analysed"], 0)
        self.assertFalse(manifest["complete"])
        self.assertTrue(any("NO file" in note for note in manifest["notes"]))


class SecretScanIsNotAnalysisTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(["app/index.php"])
        self.addCleanup(self.workspace.cleanup)

    def test_secret_scanning_alone_does_not_make_a_file_analysed(self):
        manifest = build_manifest(
            self.workspace.root,
            [declaring_result("gitleaks", scanpaths.INTENT_SECRET, extensions=())],
            ["php"],
        )
        self.assertEqual(
            manifest["code_files_analysed"], 0,
            "a secret scanner reading a file says nothing about its vulnerabilities",
        )

    def test_secret_scan_reach_is_still_reported_separately(self):
        manifest = build_manifest(
            self.workspace.root,
            [declaring_result("gitleaks", scanpaths.INTENT_SECRET, extensions=())],
            ["php"],
        )
        self.assertIn("gitleaks", manifest["secret_scanned_by"])


class BucketAttributionTestCase(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace([
            "app/index.php",                 # analysed
            "vendor/lib/guzzle.php",         # excluded by the SAST plan
            "database/schema.sql",           # no engine parses SQL
            "public/logo.png",               # not code
        ])
        self.addCleanup(self.workspace.cleanup)
        self.manifest = build_manifest(
            self.workspace.root,
            [declaring_result("semgrep", scanpaths.INTENT_SAST)],
            ["php"],
        )

    def test_each_file_lands_in_exactly_one_bucket(self):
        counts = self.manifest["counts"]
        self.assertEqual(sum(counts.values()), self.manifest["workspace_files"])

    def test_source_read_by_a_completed_scanner_is_analysed(self):
        self.assertEqual(self.manifest["counts"][BUCKET_ANALYSED], 1)

    def test_vendored_source_is_attributed_to_the_exclusion_not_to_a_failure(self):
        self.assertEqual(self.manifest["counts"][BUCKET_EXCLUDED], 1)
        self.assertEqual(self.manifest["counts"][BUCKET_SCANNER_FAILED], 0)

    def test_a_filetype_with_no_engine_is_named_as_such(self):
        self.assertEqual(self.manifest["counts"][BUCKET_NO_ENGINE], 1)
        entry = self.manifest["not_analysed"][BUCKET_NO_ENGINE]["files"][0]
        self.assertTrue(entry["file"].endswith(".sql"))
        self.assertIn("SQL", entry["reason"])

    def test_images_do_not_count_against_code_coverage(self):
        self.assertEqual(self.manifest["counts"][BUCKET_NOT_CODE], 1)
        # 4 files, 1 of which is an image: the denominator is 3, not 4.
        self.assertEqual(self.manifest["code_files"], 3)

    def test_every_unanalysed_file_carries_a_reason(self):
        for bucket in self.manifest["not_analysed"].values():
            for entry in bucket["files"]:
                self.assertTrue(entry["reason"], "%s has no reason" % entry["file"])


class StatementTestCase(unittest.TestCase):
    """The census must state its result in words, not only in numbers."""

    def test_full_coverage_says_so_plainly(self):
        workspace = Workspace(["app/index.php"])
        self.addCleanup(workspace.cleanup)
        manifest = build_manifest(
            workspace.root, [declaring_result("semgrep", scanpaths.INTENT_SAST)], ["php"]
        )
        self.assertIn("Every one of the", manifest["statement"])

    def test_partial_coverage_says_what_was_not_looked_for(self):
        workspace = Workspace(["app/index.php", "database/schema.sql"])
        self.addCleanup(workspace.cleanup)
        manifest = build_manifest(
            workspace.root, [declaring_result("semgrep", scanpaths.INTENT_SAST)], ["php"]
        )
        self.assertIn("were not looked for", manifest["statement"])
        self.assertIn("NOT read", manifest["statement"])


class FailClosedTestCase(unittest.TestCase):
    def test_an_unreadable_workspace_reports_unknown_not_complete(self):
        manifest = build_manifest(os.path.join(tempfile.gettempdir(), "does-not-exist-xyz"), [], [])
        # An empty walk is legitimate; what must never happen is a claim of
        # completeness with nothing behind it.
        self.assertFalse(manifest.get("complete"))

    def test_a_census_that_raises_reports_unavailable_with_a_warning(self):
        manifest = build_manifest(None, [], [])  # type: ignore[arg-type]
        self.assertFalse(manifest["available"])
        self.assertIn("not a statement that every file was analysed", manifest["warning"])

    def test_a_result_without_a_declaration_contributes_nothing(self):
        result = ScannerResult(tool="mystery", category_key="c")
        result.payload = {}
        result.succeed()
        self.assertEqual(scan_coverage_from_results([result]), [])


if __name__ == "__main__":
    unittest.main()
