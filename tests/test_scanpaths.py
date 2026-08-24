"""Invariants for the declared path policy.

The bug this module exists to prevent: a shared, hard-coded skip list containing
`vendor` was applied to BOTH the SAST engine and the SCA engine. For a PHP or Go
project that is where all third-party code lives, so the dependency scanner was
excluded from the only directory it had any reason to read -- and then reported
a clean scan of nothing.

So the tests here are about intent. A scan that reads dependencies must not be
handed a plan that hides them, and a scan that skips them must SAY it skipped
them, because a blind spot nobody records is indistinguishable from no findings.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.core import scanpaths  # noqa: E402


class ScaMustReadDependenciesTestCase(unittest.TestCase):
    """The regression that motivated this module."""

    def test_sca_never_excludes_vendor_for_php(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SCA, ["php"])
        self.assertNotIn("vendor", plan.patterns)
        self.assertIn("vendor", plan.vendored_scanned)

    def test_sca_never_excludes_node_modules_for_javascript(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SCA, ["javascript"])
        self.assertNotIn("node_modules", plan.patterns)

    def test_sca_reports_no_lost_coverage(self):
        for languages in (["php"], ["go"], ["javascript"], ["python"], []):
            plan = scanpaths.resolve(scanpaths.INTENT_SCA, languages)
            self.assertFalse(
                plan.loses_coverage,
                "SCA must not declare a blind spot for languages=%r" % languages,
            )
            self.assertEqual(plan.coverage_note(), "")


class SastSkipsButDeclaresTestCase(unittest.TestCase):
    def test_sast_excludes_vendor_for_php(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SAST, ["php"])
        self.assertIn("vendor", plan.patterns)

    def test_a_skipped_dependency_tree_is_always_declared(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SAST, ["php"])
        self.assertTrue(plan.loses_coverage)
        self.assertIn("vendor", plan.vendored_skipped)
        # The note must name the directory: "coverage is incomplete" that does
        # not say where is not actionable.
        self.assertIn("vendor", plan.coverage_note())
        self.assertIn("NOT analysed", plan.coverage_note())

    def test_include_dependencies_override_reads_them_and_records_the_choice(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SAST, ["php"], include_dependencies=True)
        self.assertNotIn("vendor", plan.patterns)
        self.assertFalse(plan.loses_coverage)
        self.assertTrue(any("include_dependencies" in note for note in plan.notes))

    def test_language_specific_directories_are_not_applied_to_other_languages(self):
        php = scanpaths.resolve(scanpaths.INTENT_SAST, ["php"])
        # A PHP project has no node_modules to skip; excluding it anyway would
        # hide a directory this project might genuinely be using for something.
        self.assertNotIn("node_modules", php.vendored_skipped)


class SecretScanReadsEverythingTestCase(unittest.TestCase):
    def test_secret_intent_does_not_exclude_dependencies_or_build_output(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SECRET, ["javascript"])
        for pattern in ("node_modules", "dist", "build"):
            self.assertNotIn(pattern, plan.patterns)

    def test_secret_intent_still_excludes_version_control_internals(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SECRET, ["php"])
        self.assertIn(".git", plan.patterns)


class FailClosedTestCase(unittest.TestCase):
    def test_unknown_intent_excludes_nothing_beyond_vcs_internals(self):
        plan = scanpaths.resolve("something-nobody-implemented", ["php"])
        self.assertNotIn("vendor", plan.patterns)
        self.assertNotIn("dist", plan.patterns)
        self.assertIn(".git", plan.patterns)
        self.assertFalse(plan.loses_coverage)

    def test_unknown_language_still_excludes_the_common_dependency_dirs_for_sast(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SAST, ["cobol"])
        self.assertIn("node_modules", plan.patterns)
        self.assertTrue(plan.loses_coverage)


class PatternMatchingTestCase(unittest.TestCase):
    """Segment-wise matching. Substring matching would silently hide real code."""

    def test_directory_segment_matches(self):
        self.assertTrue(scanpaths.is_excluded("vendor/lib/thing.php", ["vendor"]))
        self.assertTrue(scanpaths.is_excluded("app/vendor/lib/thing.php", ["vendor"]))

    def test_a_filename_that_merely_contains_the_pattern_is_not_excluded(self):
        self.assertFalse(scanpaths.is_excluded("app/vendored_ui.php", ["vendor"]))
        self.assertFalse(scanpaths.is_excluded("app/binary_upload.php", ["bin"]))

    def test_a_directory_whose_name_merely_contains_the_pattern_is_not_excluded(self):
        self.assertFalse(scanpaths.is_excluded("app/vendors/thing.php", ["vendor"]))

    def test_the_file_itself_is_never_treated_as_a_directory(self):
        # `build` as a FILE must not exclude itself as though it were a directory.
        self.assertFalse(scanpaths.is_excluded("build", ["build"]))

    def test_windows_separators_are_handled(self):
        self.assertTrue(scanpaths.is_excluded("app\\vendor\\lib\\thing.php", ["vendor"]))


class PlanIsSerialisableTestCase(unittest.TestCase):
    def test_to_dict_carries_the_blind_spot_into_the_report(self):
        payload = scanpaths.resolve(scanpaths.INTENT_SAST, ["php"]).to_dict()
        self.assertTrue(payload["loses_coverage"])
        self.assertIn("vendor", payload["vendored_skipped"])
        self.assertTrue(payload["coverage_note"])

    def test_patterns_are_deduplicated_and_stable(self):
        plan = scanpaths.resolve(scanpaths.INTENT_SAST, ["python", "python"])
        self.assertEqual(len(plan.patterns), len(set(plan.patterns)))
        self.assertEqual(plan.patterns, scanpaths.resolve(scanpaths.INTENT_SAST, ["python"]).patterns)


if __name__ == "__main__":
    unittest.main()
