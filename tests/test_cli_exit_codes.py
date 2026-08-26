"""What can and cannot make this program exit non-zero.

The exit code is the only part of a run a CI system reads by default, so it is
the part that decides whether the stages after a security scan get to run at
all. That makes it worth pinning separately from the verdicts it reflects.

The contract, in one line: **a finding never exits non-zero; a framework that
cannot substantiate its own output always can.**

These tests drive `main()` end to end over real fixture directories rather than
calling the resolver in isolation, because the defect worth catching is not
"the resolver returns the wrong number" -- it is "some other code path exits
before the resolver is ever reached".
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework import cli  # noqa: E402


def run_cli(workspace: str, output: str, *extra: str) -> int:
    """Invoke the real entrypoint, with its logging captured."""
    argv = [
        "run",
        "--workspace", workspace,
        "--output", output,
        "--environment", "test",
        "--no-enrichment",
    ]
    argv.extend(extra)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        return cli.main(argv)


class ExitCodes(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.mkdtemp(prefix="devsecops-exit-")
        # A source file and a manifest, so detection has something to work with
        # and several categories are genuinely applicable rather than skipped.
        with open(os.path.join(cls.workspace, "app.py"), "w", encoding="utf-8") as handle:
            handle.write("import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n")
        with open(os.path.join(cls.workspace, "requirements.txt"), "w", encoding="utf-8") as handle:
            handle.write("requests==2.6.0\n")
        cls.outputs = tempfile.mkdtemp(prefix="devsecops-exit-out-")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.workspace, ignore_errors=True)
        shutil.rmtree(cls.outputs, ignore_errors=True)

    def _output(self, name: str) -> str:
        return os.path.join(self.outputs, name)

    def test_the_default_is_exit_zero(self):
        """No flag, no failure -- whatever the scan found."""
        self.assertEqual(run_cli(self.workspace, self._output("default")), cli.EXIT_OK)

    def test_the_default_still_writes_every_report(self):
        """Exiting zero must mean the work was done, not that it was skipped."""
        output = self._output("artefacts")
        self.assertEqual(run_cli(self.workspace, output), cli.EXIT_OK)
        for artefact in ("final-report.json", "normalized-findings.json", "findings.csv",
                         "security.sarif", "report.md", "security-report.pdf",
                         "evidence-manifest.json"):
            self.assertTrue(
                os.path.isfile(os.path.join(output, artefact)),
                "%s was not written; a zero exit code must not mean a short-circuited run"
                % artefact,
            )

    def test_the_report_records_a_completed_pipeline_and_a_decision(self):
        output = self._output("report")
        run_cli(self.workspace, output)
        with open(os.path.join(output, "final-report.json"), encoding="utf-8") as handle:
            report = json.load(handle)

        self.assertEqual(report["pipeline"]["status"], "COMPLETED")
        self.assertTrue(report["pipeline"]["artifacts_written"])
        # The decision is present and is never invented as a favourable one.
        self.assertIn(report["readiness"]["decision"],
                      ("READY", "CONDITIONALLY_READY", "NOT_READY", "UNKNOWN"))
        self.assertTrue(report["readiness"]["decision_rationale"])
        self.assertTrue(report["readiness"]["dimensions"])

    def test_fail_on_decision_reports_a_decision_that_is_not_ready(self):
        code = run_cli(self.workspace, self._output("decision"), "--fail-on", "decision")
        self.assertEqual(code, cli.EXIT_NOT_DEPLOYABLE)

    def test_fail_on_security_reproduces_the_legacy_behaviour(self):
        """No scanners on this runner, so SECURITY is NOT_VERIFIED -- exit 3."""
        code = run_cli(self.workspace, self._output("security"), "--fail-on", "security")
        self.assertEqual(code, cli.EXIT_SECURITY_NOT_VERIFIED)

    def test_the_deprecated_flag_means_exactly_what_it_used_to(self):
        legacy = run_cli(self.workspace, self._output("legacy"), "--fail-on-security")
        explicit = run_cli(self.workspace, self._output("explicit"), "--fail-on", "security")
        self.assertEqual(legacy, explicit)

    def test_the_deprecated_flag_wins_over_the_new_selector(self):
        """An existing caller keeps its behaviour even if fail_on is also set."""
        code = run_cli(
            self.workspace, self._output("both"), "--fail-on", "never", "--fail-on-security"
        )
        self.assertEqual(code, cli.EXIT_SECURITY_NOT_VERIFIED)

    def test_an_unknown_stage_is_a_framework_error_not_a_verdict(self):
        code = run_cli(self.workspace, self._output("badstage"), "--stage", "NOT_A_STAGE")
        self.assertEqual(code, cli.EXIT_FRAMEWORK_ERROR)

    def test_a_broken_policy_file_is_a_framework_error_not_a_pass(self):
        bad = os.path.join(self.outputs, "bad-policy.yml")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("readiness:\n  weights: not-a-mapping\n")
        code = run_cli(self.workspace, self._output("badpolicy"), "--policy", bad)
        self.assertEqual(
            code, cli.EXIT_FRAMEWORK_ERROR,
            "a policy that cannot be read must be loud, never silently defaulted",
        )

    def test_an_unparseable_coverage_figure_does_not_fail_the_run(self):
        """It is recorded as NOT_REPORTED. A bad input is not a framework error."""
        output = self._output("badcoverage")
        code = run_cli(self.workspace, output, "--test-coverage-percent", "not-a-number")
        self.assertEqual(code, cli.EXIT_OK)
        with open(os.path.join(output, "final-report.json"), encoding="utf-8") as handle:
            report = json.load(handle)
        dimension = next(
            d for d in report["readiness"]["dimensions"] if d["key"] == "test_coverage"
        )
        self.assertEqual(dimension["state"], "NOT_REPORTED")
        self.assertIsNone(dimension["score"], "an unparseable figure must not score as zero")


class OutputsForCallers(unittest.TestCase):
    """The step outputs a deployment job gates on must actually be emitted."""

    def test_every_readiness_output_is_written(self):
        workspace = tempfile.mkdtemp(prefix="devsecops-out-")
        outputs = tempfile.mkdtemp(prefix="devsecops-out-o-")
        github_output = os.path.join(outputs, "gh-output.txt")
        try:
            with open(os.path.join(workspace, "app.py"), "w", encoding="utf-8") as handle:
                handle.write("x = 1\n")
            previous = os.environ.get("GITHUB_OUTPUT")
            os.environ["GITHUB_OUTPUT"] = github_output
            try:
                run_cli(workspace, os.path.join(outputs, "results"))
            finally:
                if previous is None:
                    os.environ.pop("GITHUB_OUTPUT", None)
                else:
                    os.environ["GITHUB_OUTPUT"] = previous

            with open(github_output, encoding="utf-8") as handle:
                emitted = dict(
                    line.split("=", 1) for line in handle.read().splitlines() if "=" in line
                )
            for key in ("security_status", "pipeline_status", "evidence_status",
                        "deployment_decision", "deployment_permitted", "readiness_percent",
                        "readiness_assurance_percent", "critical_findings", "high_findings"):
                self.assertIn(key, emitted, "step output %r was not written" % key)
            self.assertIn(emitted["deployment_permitted"], ("true", "false"))
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
            shutil.rmtree(outputs, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
