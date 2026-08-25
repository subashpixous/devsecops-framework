"""Cross-scanner correlation contract tests.

The invariant under test is the one that makes this module safe: correlation is
ADDITIVE. It records that two scanners agree; it never merges, renames or drops
a finding, and it never lets one suppression cover another scanner's evidence.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.core.correlation import correlate  # noqa: E402
from framework.core.schema import Finding  # noqa: E402


def _f(tool, file="src/login.php", line=42, cwe="CWE-89", severity="HIGH", description="SQL injection"):
    return Finding(
        tool=tool, file=file, line=line, cwe=cwe, severity=severity,
        description=description, category="vulnerability",
        rule="%s-rule" % tool, native_id="%s-%d" % (tool, line),
    )


class Corroboration(unittest.TestCase):
    def test_two_scanners_on_the_same_defect_are_linked(self):
        sonar, semgrep = _f("sonarqube"), _f("semgrep")
        summary = correlate([sonar, semgrep])

        self.assertEqual(len(summary.corroborated_groups), 1)
        group = summary.corroborated_groups[0]
        self.assertEqual(sorted(set(group.tools)), ["semgrep", "sonarqube"])
        self.assertTrue(group.corroborated)

    def test_each_finding_learns_who_else_found_it(self):
        sonar, semgrep = _f("sonarqube"), _f("semgrep")
        correlate([sonar, semgrep])
        self.assertEqual(sonar.also_detected_by, ["semgrep"])
        self.assertEqual(semgrep.also_detected_by, ["sonarqube"])

    def test_correlated_findings_share_an_id(self):
        sonar, semgrep = _f("sonarqube"), _f("semgrep")
        correlate([sonar, semgrep])
        self.assertTrue(sonar.correlation_id)
        self.assertEqual(sonar.correlation_id, semgrep.correlation_id)

    def test_nearby_lines_still_correlate(self):
        sonar, semgrep = _f("sonarqube", line=42), _f("semgrep", line=44)
        self.assertEqual(len(correlate([sonar, semgrep]).corroborated_groups), 1)

    def test_distant_lines_are_separate_defects(self):
        a, b = _f("sonarqube", line=42), _f("semgrep", line=300)
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 0)


class NothingIsLost(unittest.TestCase):
    """The property that makes correlation safe here."""

    def test_no_finding_is_removed(self):
        findings = [_f("sonarqube"), _f("semgrep"), _f("trivy", cwe="CWE-1104")]
        correlate(findings)
        self.assertEqual(len(findings), 3)

    def test_fingerprints_are_untouched(self):
        sonar, semgrep = _f("sonarqube"), _f("semgrep")
        before = (sonar.fingerprint, semgrep.fingerprint)
        correlate([sonar, semgrep])
        self.assertEqual((sonar.fingerprint, semgrep.fingerprint), before)
        self.assertNotEqual(
            sonar.fingerprint, semgrep.fingerprint,
            "correlated findings must keep DISTINCT identities, or one exception "
            "entry would suppress both",
        )

    def test_severity_and_lifecycle_are_untouched(self):
        sonar = _f("sonarqube", severity="CRITICAL")
        sonar.lifecycle = "EXISTING"
        correlate([sonar, _f("semgrep", severity="LOW")])
        self.assertEqual(sonar.severity, "CRITICAL")
        self.assertEqual(sonar.lifecycle, "EXISTING")


class ConservativeLinking(unittest.TestCase):
    """A wrong link is worse than no link."""

    def test_same_file_different_cwe_does_not_correlate(self):
        sqli = _f("sonarqube", cwe="CWE-89")
        xss = _f("semgrep", cwe="CWE-79")
        self.assertEqual(len(correlate([sqli, xss]).corroborated_groups), 0)

    def test_same_cwe_different_file_does_not_correlate(self):
        a = _f("sonarqube", file="src/a.php")
        b = _f("semgrep", file="src/b.php")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 0)

    def test_findings_without_a_cwe_never_correlate(self):
        a, b = _f("sonarqube", cwe=""), _f("semgrep", cwe="")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 0)

    def test_findings_without_a_file_never_correlate(self):
        a, b = _f("sonarqube", file=""), _f("semgrep", file="")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 0)

    def test_one_scanner_reporting_twice_is_not_corroboration(self):
        a, b = _f("semgrep", line=42), _f("semgrep", line=43)
        self.assertEqual(
            len(correlate([a, b]).corroborated_groups), 0,
            "the same engine reporting twice is repetition, not independent confirmation",
        )

    def test_multi_cwe_findings_correlate_on_any_shared_cwe(self):
        a = _f("sonarqube", cwe="CWE-89,CWE-20")
        b = _f("semgrep", cwe="CWE-20")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 1)

    def test_bare_numeric_cwe_is_normalised(self):
        a, b = _f("sonarqube", cwe="89"), _f("semgrep", cwe="CWE-89")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 1)

    def test_paths_differing_only_by_separator_correlate(self):
        a = _f("sonarqube", file="src\\login.php")
        b = _f("semgrep", file="src/login.php")
        self.assertEqual(len(correlate([a, b]).corroborated_groups), 1)


class Reporting(unittest.TestCase):
    def test_statement_says_when_nothing_is_corroborated(self):
        statement = correlate([_f("semgrep")]).statement()
        self.assertIn("single engine", statement)

    def test_statement_reports_corroboration(self):
        statement = correlate([_f("sonarqube"), _f("semgrep")]).statement()
        self.assertIn("independently reported", statement)

    def test_summary_serialises(self):
        payload = correlate([_f("sonarqube"), _f("semgrep")]).to_dict()
        self.assertEqual(payload["corroborated_defects"], 1)
        self.assertEqual(payload["findings_correlated"], 2)
        self.assertEqual(payload["groups"][0]["tool_count"], 2)

    def test_uncorroborated_groups_are_not_reported_as_groups(self):
        payload = correlate([_f("semgrep")]).to_dict()
        self.assertEqual(payload["groups"], [])

    def test_empty_input_is_safe(self):
        summary = correlate([])
        self.assertEqual(summary.findings_correlated, 0)
        self.assertEqual(summary.to_dict()["corroborated_defects"], 0)


if __name__ == "__main__":
    unittest.main()
