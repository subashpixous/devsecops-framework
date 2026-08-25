"""Release consistency invariants.

These tests exist because two shipping defects reached a release:

  * `security-pipeline.yml` declared `active_phase: 6` while the bundled policy
    declared 7, so two implemented categories never executed for any consumer
    using the reusable workflow with defaults. The categories reported
    NOT_IMPLEMENTED -- correct behaviour for a phase that has not shipped, and
    completely wrong for one that had.

  * `examples/caller-workflow.yml` stayed pinned to an old release while the
    onboarding guide told every integrator to copy that file verbatim.

Neither is detectable by testing Python alone: both live in the seam between
the code and the artefacts that ship it. They are asserted here so the seam
cannot silently reopen.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework import __version__  # noqa: E402
from framework.core.categories import CATEGORY_REGISTRY  # noqa: E402
from framework.core.policy import Policy  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPELINE = os.path.join(ROOT, ".github", "workflows", "security-pipeline.yml")
EXAMPLE = os.path.join(ROOT, "examples", "caller-workflow.yml")
VERSION_FILE = os.path.join(ROOT, "VERSION")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _workflow_input_default(text, input_name):
    """Read the `default:` of one workflow_call input without a YAML parser.

    PyYAML is a dependency, but parsing the whole workflow here would couple
    these tests to the file's structure. The inputs block is flat and stable, so
    a scoped regex is both sufficient and more legible in a failure message.
    """
    pattern = re.compile(
        r"^      %s:\s*$\n((?:^        .*$\n)+)" % re.escape(input_name),
        re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return None
    block = match.group(1)
    default = re.search(r"^        default:\s*(.+?)\s*$", block, re.MULTILINE)
    return default.group(1) if default else None


class ActivePhaseConsistency(unittest.TestCase):
    """The shipped workflow must not run the framework behind its own policy."""

    def test_workflow_active_phase_matches_bundled_policy(self):
        policy = Policy.load()
        default = _workflow_input_default(_read(PIPELINE), "active_phase")
        self.assertIsNotNone(default, "security-pipeline.yml declares no active_phase input")
        self.assertEqual(
            int(default),
            policy.active_phase,
            "security-pipeline.yml ships active_phase=%s but default-policy.yml declares %d. "
            "Every category whose phase is above the workflow value reports NOT_IMPLEMENTED "
            "and its collector never runs." % (default, policy.active_phase),
        )

    def test_bundled_policy_covers_every_implemented_category(self):
        """The policy phase must not sit below the highest shipped category."""
        policy = Policy.load()
        highest = max(category.phase for category in CATEGORY_REGISTRY)
        self.assertGreaterEqual(
            policy.active_phase,
            highest,
            "default-policy.yml declares active_phase=%d but the category registry contains "
            "phase %d. Categories above the active phase never execute."
            % (policy.active_phase, highest),
        )

    def test_no_category_is_stranded_above_the_workflow_default(self):
        """End to end: nothing implemented may be unreachable through the workflow."""
        default = int(_workflow_input_default(_read(PIPELINE), "active_phase"))
        stranded = sorted(c.key for c in CATEGORY_REGISTRY if c.phase > default)
        self.assertEqual(
            [],
            stranded,
            "These implemented categories cannot execute through the shipped workflow: %s"
            % ", ".join(stranded),
        )


class VersionConsistency(unittest.TestCase):
    """One version number, stated identically everywhere it is stated."""

    def test_version_file_matches_package_version(self):
        self.assertEqual(_read(VERSION_FILE).strip(), __version__)

    def test_readme_states_the_current_release(self):
        self.assertIn(
            "v%s" % __version__,
            _read(README),
            "README.md does not mention the current release v%s" % __version__,
        )

    def test_changelog_has_an_entry_for_the_current_version(self):
        self.assertRegex(
            _read(CHANGELOG),
            r"##\s*\[%s\]" % re.escape(__version__),
            "CHANGELOG.md has no section for version %s" % __version__,
        )


class ExampleWorkflowConsistency(unittest.TestCase):
    """The file the onboarding guide tells integrators to copy must be current."""

    def test_example_pins_the_current_release(self):
        text = _read(EXAMPLE)
        refs = re.findall(r"security-pipeline\.yml@(\S+)", text)
        self.assertTrue(refs, "examples/caller-workflow.yml calls no reusable workflow")
        active = [ref for ref in refs if not ref.startswith("<")]
        self.assertTrue(active, "examples/caller-workflow.yml has no concrete pin")
        for ref in active:
            self.assertEqual(
                ref,
                "v%s" % __version__,
                "examples/caller-workflow.yml pins %s but the current release is v%s. "
                "docs/ONBOARDING.md instructs integrators to copy this file verbatim, so a "
                "stale pin ships a stale framework." % (ref, __version__),
            )

    def test_readme_usage_block_is_not_pinned_to_a_stale_release(self):
        """README shows a placeholder; it must not hard-code an old version."""
        refs = re.findall(r"security-pipeline\.yml@(\S+)", _read(README))
        for ref in refs:
            if ref.startswith("<"):
                continue  # documented placeholder, e.g. @<sha>
            self.assertEqual(ref, "v%s" % __version__)


class CategoryCountConsistency(unittest.TestCase):
    """Documentation must not understate the control set."""

    def test_readme_category_count_matches_the_registry(self):
        stated = re.search(r"All (\d+) security categories", _read(README))
        self.assertIsNotNone(stated, "README no longer states a category count")
        self.assertEqual(
            int(stated.group(1)),
            len(CATEGORY_REGISTRY),
            "README claims %s categories; the registry declares %d."
            % (stated.group(1), len(CATEGORY_REGISTRY)),
        )


class WorkflowValidity(unittest.TestCase):
    """The shipped workflows must parse, and must stay supply-chain hardened."""

    WORKFLOWS = (
        os.path.join(ROOT, ".github", "workflows", "security-pipeline.yml"),
        os.path.join(ROOT, ".github", "workflows", "self-test.yml"),
        os.path.join(ROOT, ".github", "workflows", "pipeline-validation.yml"),
        EXAMPLE,
    )

    def test_every_workflow_is_valid_yaml(self):
        import yaml

        for path in self.WORKFLOWS:
            with self.subTest(workflow=os.path.basename(path)):
                with open(path, "r", encoding="utf-8") as handle:
                    self.assertIsInstance(yaml.safe_load(handle), dict)

    def test_third_party_actions_are_pinned_to_commit_shas(self):
        """A tag can be silently repointed at different code. A SHA cannot."""
        pattern = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
        for path in self.WORKFLOWS:
            text = _read(path)
            for ref in pattern.findall(text):
                if "/.github/workflows/" in ref:
                    continue  # our own reusable workflow, pinned by release tag
                with self.subTest(workflow=os.path.basename(path), action=ref):
                    self.assertRegex(
                        ref,
                        r"@[0-9a-f]{40}$",
                        "%s is not pinned to a full commit SHA" % ref,
                    )

    def test_scanner_downloads_are_checksum_verified(self):
        """A truncated download installs a broken scanner that reports nothing."""
        text = _read(PIPELINE)
        self.assertIn("verify_sha256", text)
        for tool in ("gitleaks", "trivy", "nuclei", "cosign"):
            with self.subTest(tool=tool):
                self.assertRegex(
                    text,
                    r"verify_sha256[^\n]*%s" % tool,
                    "%s is downloaded without checksum verification" % tool,
                )

    def test_no_scanner_is_installed_from_a_floating_latest(self):
        """`latest` makes the evidence manifest record a version nobody chose."""
        self.assertNotIn(
            "releases/latest/download",
            _read(PIPELINE),
            "a scanner is being pulled from a floating 'latest' release",
        )

    def test_the_pipeline_never_grants_write_beyond_security_events(self):
        import yaml

        with open(PIPELINE, "r", encoding="utf-8") as handle:
            workflow = yaml.safe_load(handle)
        permissions = workflow["jobs"]["security"].get("permissions") or {}
        for scope, level in permissions.items():
            if scope == "security-events":
                continue
            with self.subTest(scope=scope):
                self.assertEqual(
                    level, "read",
                    "the security job grants %s: %s; the only write scope permitted is "
                    "security-events (for SARIF upload)" % (scope, level),
                )


class DependencyPinning(unittest.TestCase):
    """A security tool must know which code produced its verdict."""

    def test_runtime_dependencies_are_pinned_exactly(self):
        requirements = _read(os.path.join(ROOT, "requirements.txt"))
        declared = [
            line.strip() for line in requirements.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertTrue(declared, "requirements.txt declares no dependencies")
        for line in declared:
            with self.subTest(requirement=line):
                self.assertIn("==", line, "%s is not pinned to an exact version" % line)


if __name__ == "__main__":
    unittest.main()
