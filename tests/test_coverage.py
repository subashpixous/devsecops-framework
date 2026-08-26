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
    SCANNER_COMPLETED_DEGRADED,
    SCANNER_FAILED_TO_COMPLETE,
    SCANNER_UNAVAILABLE,
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
        coverages = scan_coverage_from_results([result])

        # It is listed -- a scanner that disappears from the census is the exact
        # silent gap this module exists to prevent -- but it is credited with
        # nothing, which is the invariant that matters.
        self.assertEqual(len(coverages), 1)
        entry = coverages[0]
        self.assertEqual(entry.tool, "mystery")
        self.assertFalse(entry.completed)
        self.assertEqual(entry.status, "coverage_not_declared")
        self.assertFalse(entry.reads("app.py", ".py"))

    def test_an_undeclared_scanner_credits_no_file_in_the_manifest(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "app.py"), "w", encoding="utf-8") as handle:
                handle.write("x = 1\n")
            result = ScannerResult(tool="mystery", category_key="c")
            result.payload = {}
            result.succeed()
            manifest = build_manifest(workspace, [result], ["python"])

        self.assertEqual(manifest["code_files_analysed"], 0)
        self.assertFalse(manifest["complete"])


if __name__ == "__main__":
    unittest.main()


# --- Files the engine could not parse ----------------------------------------
#
# TNCWWB run 32929294329 exposed a coverage over-claim: Semgrep reported it could
# not parse Core.php, yet the census still counted that file as `analysed`.
# `reads()` decided on completed + extension + exclusions only, so a per-file
# parse failure was invisible to it and the published coverage figure overstated
# what the engine had actually read. The gate caught it as a caveat; the census
# should never have produced the wrong number.


class EngineCouldNotParse(unittest.TestCase):
    def _manifest(self, unparsed):
        workspace = tempfile.mkdtemp()
        for name in ("Core.php", "index.php"):
            with open(os.path.join(workspace, name), "w", encoding="utf-8") as handle:
                handle.write("<?php\n")
        result = ScannerResult(tool="semgrep", category_key="sast_semgrep")
        result.metadata["coverage"] = {
            "exclusions": {"intent": "sast", "patterns": []},
            "extensions": [".php"],
            "unparsed_files": list(unparsed),
        }
        result.payload = {}
        result.succeed()
        return build_manifest(workspace, [result], ["php"])

    def test_an_unparseable_file_is_not_counted_as_analysed(self):
        """The exact TNCWWB defect."""
        manifest = self._manifest(["Core.php"])
        self.assertEqual(manifest["code_files"], 2)
        self.assertEqual(
            manifest["code_files_analysed"], 1,
            "a file the engine could not parse must not be credited as analysed",
        )
        self.assertEqual(manifest["code_files_not_analysed"], 1)
        self.assertFalse(manifest["complete"])

    def test_it_lands_in_its_own_bucket_with_a_named_reason(self):
        manifest = self._manifest(["Core.php"])
        self.assertEqual(manifest["counts"]["engine_could_not_parse"], 1)
        entry = manifest["not_analysed"]["engine_could_not_parse"]["files"][0]
        self.assertEqual(entry["file"], "Core.php")
        self.assertIn("could not parse", entry["reason"])
        self.assertIn("semgrep", entry["reason"])

    def test_the_statement_names_the_parse_failure(self):
        self.assertIn(
            "could not parse them", self._manifest(["Core.php"])["statement"]
        )

    def test_a_basename_report_matches_a_nested_path(self):
        """Engines report a basename or a relative path depending on invocation."""
        workspace = tempfile.mkdtemp()
        nested = os.path.join(workspace, "src", "lib")
        os.makedirs(nested)
        with open(os.path.join(nested, "Core.php"), "w", encoding="utf-8") as handle:
            handle.write("<?php\n")
        result = ScannerResult(tool="semgrep", category_key="sast_semgrep")
        result.metadata["coverage"] = {
            "exclusions": {"intent": "sast", "patterns": []},
            "extensions": [".php"],
            "unparsed_files": ["Core.php"],
        }
        result.payload = {}
        result.succeed()
        manifest = build_manifest(workspace, [result], ["php"])
        self.assertEqual(manifest["code_files_analysed"], 0)
        self.assertEqual(manifest["counts"]["engine_could_not_parse"], 1)

    def test_no_parse_failures_leaves_coverage_unchanged(self):
        manifest = self._manifest([])
        self.assertEqual(manifest["code_files_analysed"], 2)
        self.assertEqual(manifest["counts"]["engine_could_not_parse"], 0)
        self.assertTrue(manifest["complete"])

    def test_parse_failure_is_distinct_from_having_no_engine(self):
        """`engine_could_not_parse` must not be conflated with either neighbour."""
        manifest = self._manifest(["Core.php"])
        self.assertEqual(manifest["counts"]["no_scanner_for_filetype"], 0)
        self.assertEqual(manifest["counts"]["scanner_did_not_complete"], 0)
        self.assertEqual(manifest["counts"]["engine_could_not_parse"], 1)


class RanButDegradedIsNotAFailure(unittest.TestCase):
    """A tool that exits 0 and returns a valid report has COMPLETED.

    The census previously had no state for "ran cleanly, result judged
    degraded", so a PARTIAL result fell through to `scanner_failed` and was
    published as "did NOT complete". For Trivy SCA on a project with no
    dependency manifest that sentence was simply false: the process exited 0 in
    5.5s with a valid SchemaVersion-2 report and no stderr.

    The distinction matters because the two conditions have different owners. A
    scanner that failed is the runner's problem; an empty dependency inventory
    is the project's. Coverage credit is identical either way -- nothing -- so
    this is about what the report SAYS, which for this framework is the product.
    """

    def _sca_result(self, warning="Trivy returned no 'Results' section."):
        """Trivy SCA as a real run leaves it: ran, valid output, no inventory."""
        result = ScannerResult(tool="trivy-sca", category_key="sca_dependencies")
        plan = scanpaths.resolve("sca", ["php"])
        result.metadata["coverage"] = {
            "exclusions": plan.to_dict(),
            "extensions": [],  # SCA declares no extension filter: every file is in scope
        }
        result.payload = {"SchemaVersion": 2}
        result.partial(warning)   # degradation recorded, NO error
        result.succeed()          # happy path still runs; degraded blocks promotion
        return result

    def _row(self, result, files=("index.php", "app/Model.php")):
        workspace = Workspace(list(files))
        self.addCleanup(workspace.cleanup)
        manifest = build_manifest(workspace.root, [result], ["php"])
        rows = {r["tool"]: r for r in manifest["per_scanner"]}
        return manifest, rows["trivy-sca"]

    def test_a_partial_result_without_errors_is_not_reported_as_failed(self):
        """The exact TNCWWB Trivy defect."""
        _, row = self._row(self._sca_result())
        self.assertEqual(row["status"], SCANNER_COMPLETED_DEGRADED)
        self.assertNotEqual(
            row["status"], SCANNER_FAILED_TO_COMPLETE,
            "a process that exited 0 with a valid report did not fail",
        )

    def test_the_reason_is_the_collectors_own_warning_not_a_generic_failure(self):
        _, row = self._row(self._sca_result("no lockfile or manifest was recognised"))
        self.assertIn("no lockfile or manifest was recognised", row["status_reason"])
        self.assertNotIn("did not complete successfully", row["status_reason"])

    def test_the_published_sentence_does_not_claim_the_scanner_failed(self):
        _, row = self._row(self._sca_result())
        statement = row["statement"]
        self.assertNotIn("did NOT complete", statement)
        self.assertIn("ran to completion", statement)
        self.assertIn("degraded", statement)

    def test_nothing_is_credited_to_a_degraded_scanner(self):
        """The fix must not buy a truthful label with a false coverage claim."""
        _, row = self._row(self._sca_result())
        self.assertEqual(row["analysed"], 0)
        self.assertFalse(row["completed"])

    def test_it_is_excluded_from_the_scanners_failed_note(self):
        manifest, _ = self._row(self._sca_result())
        self.assertNotIn("trivy-sca", manifest["scanners_failed"])
        joined = " ".join(manifest["notes"])
        self.assertNotIn("Scanner(s) that did NOT complete: trivy-sca", joined)

    def test_it_is_still_reported_and_never_silently_dropped(self):
        manifest, row = self._row(self._sca_result())
        self.assertIn("trivy-sca", [r["tool"] for r in manifest["per_scanner"]])
        self.assertIn("degraded result", " ".join(manifest["notes"]))
        self.assertTrue(row["status_reason"])

    def test_a_recorded_error_still_reports_a_real_failure(self):
        """Only an error-free PARTIAL is a completion. A failure stays a failure."""
        result = ScannerResult(tool="trivy-sca", category_key="sca_dependencies")
        plan = scanpaths.resolve("sca", ["php"])
        result.metadata["coverage"] = {"exclusions": plan.to_dict(), "extensions": []}
        result.fail("trivy did not complete: exit 2")
        _, row = self._row(result)
        self.assertEqual(row["status"], SCANNER_FAILED_TO_COMPLETE)
        self.assertIn("did NOT complete", row["statement"])

    def test_a_missing_binary_is_still_reported_as_unavailable(self):
        """The unavailable branch must keep priority over the degraded branch."""
        result = ScannerResult(tool="trivy-sca", category_key="sca_dependencies")
        plan = scanpaths.resolve("sca", ["php"])
        result.metadata["coverage"] = {"exclusions": plan.to_dict(), "extensions": []}
        result.fail("trivy is not installed or not on PATH")
        _, row = self._row(result)
        self.assertEqual(row["status"], SCANNER_UNAVAILABLE)

    def test_headline_coverage_is_unchanged_by_a_degraded_sca_scanner(self):
        """SCA is not SAST: it must not move the coverage percentage either way."""
        sast = declaring_result("semgrep", "sast")
        workspace = Workspace(["index.php", "app/Model.php"])
        self.addCleanup(workspace.cleanup)
        before = build_manifest(workspace.root, [sast], ["php"])
        after = build_manifest(workspace.root, [sast, self._sca_result()], ["php"])
        self.assertEqual(before["coverage_percent"], after["coverage_percent"])
        self.assertEqual(after["counts"]["scanner_did_not_complete"], 0)
