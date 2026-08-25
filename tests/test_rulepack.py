"""Framework secure-coding rule pack: composition, selection and rule quality.

The single most important test in this file is
`CompositionIsAdditive.test_project_rules_do_not_remove_the_security_packs`.

Before this pack existed, `SEMGREP_RULES` REPLACED the entire Semgrep
configuration. Adding one custom rule therefore switched off `p/security-audit`
and `p/owasp-top-ten` -- a coverage loss that looked exactly like a coverage
gain, and that no report would have shown. Everything else here exists to keep
that from coming back, and to stop a malformed rule of ours from taking down the
whole SAST category on someone else's runner.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.adapters.semgrep_adapter import KNOWN_CATEGORIES  # noqa: E402
from framework.collectors.semgrep import SECURITY_CONFIGS, SemgrepCollector  # noqa: E402
from framework.core.rulepack import (  # noqa: E402
    LANGUAGE_DIRECTORIES,
    REQUIRED_METADATA_FIELDS,
    RULE_ID_PREFIX,
    RULES_ROOT,
    compose_configs,
    discover_rule_files,
    rule_inventory,
    select_rules,
    validate_rule_document,
)


def _yaml(path):
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _all_rules():
    """Every rule the framework ships, as (file, rule) pairs."""
    out = []
    for rule_file in discover_rule_files():
        if rule_file.error or not rule_file.rule_ids:
            continue
        document = _yaml(rule_file.path)
        for rule in document.get("rules") or []:
            out.append((rule_file, rule))
    return out


# --- Rule pack integrity -----------------------------------------------------


class RulePackIntegrity(unittest.TestCase):
    def test_every_shipped_rule_file_is_valid(self):
        invalid = [f for f in discover_rule_files() if f.error]
        self.assertEqual(
            [], [(os.path.basename(f.path), f.error) for f in invalid],
            "a malformed rule file fails the entire Semgrep invocation, which would convert a "
            "rule-authoring mistake into a lost SAST category on a consumer's runner",
        )

    def test_the_pack_actually_contains_rules(self):
        self.assertGreater(rule_inventory()["total_rules"], 0)

    def test_every_directory_is_language_mapped(self):
        """An unmapped directory never runs; that must be a test failure, not a surprise."""
        for entry in sorted(os.listdir(RULES_ROOT)):
            if os.path.isdir(os.path.join(RULES_ROOT, entry)):
                with self.subTest(directory=entry):
                    self.assertIn(entry, LANGUAGE_DIRECTORIES)

    def test_rule_ids_are_namespaced_and_unique(self):
        ids = [rule.get("id") for _, rule in _all_rules()]
        for rule_id in ids:
            with self.subTest(rule=rule_id):
                self.assertTrue(str(rule_id).startswith(RULE_ID_PREFIX))
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule ids produce duplicate findings")

    def test_every_rule_documents_its_rationale(self):
        """A rule that cannot be justified to a reviewer should not ship."""
        for rule_file, rule in _all_rules():
            metadata = rule.get("metadata") or {}
            for required in REQUIRED_METADATA_FIELDS:
                with self.subTest(rule=rule.get("id"), field=required):
                    self.assertTrue(str(metadata.get(required) or "").strip())

    def test_every_rule_declares_a_cwe(self):
        for _, rule in _all_rules():
            with self.subTest(rule=rule.get("id")):
                self.assertRegex(str((rule.get("metadata") or {}).get("cwe")), r"^CWE-\d+$")

    def test_declared_categories_are_all_scored_by_policy(self):
        """A category the policy does not score would silently escape thresholds."""
        from framework.core.policy import Policy

        scored = set(Policy.load().security_finding_categories)
        for _, rule in _all_rules():
            category = str((rule.get("metadata") or {}).get("category") or "").lower()
            with self.subTest(rule=rule.get("id"), category=category):
                self.assertIn(category, KNOWN_CATEGORIES)
                self.assertIn(category, scored)

    def test_rule_languages_match_their_directory(self):
        """A python rule in the php directory would fire on the wrong files."""
        expected = {
            "csharp": {"csharp"}, "python": {"python"}, "php": {"php"},
            "java": {"java", "kotlin"}, "javascript": {"js", "ts", "javascript", "typescript"},
            "common": {"generic", "regex"},
        }
        for rule_file, rule in _all_rules():
            allowed = expected.get(rule_file.directory)
            if not allowed:
                continue
            for language in rule.get("languages") or []:
                with self.subTest(rule=rule.get("id"), language=language):
                    self.assertIn(str(language).lower(), allowed)

    def test_high_severity_rules_carry_stated_confidence(self):
        for _, rule in _all_rules():
            if rule.get("severity") == "ERROR":
                with self.subTest(rule=rule.get("id")):
                    self.assertIn(
                        str((rule.get("metadata") or {}).get("confidence")).upper(),
                        {"HIGH", "MEDIUM"},
                        "an ERROR-severity rule asserted on LOW confidence is noise",
                    )


# --- Validation catches bad rules -------------------------------------------


class ValidationRejectsBadRules(unittest.TestCase):
    def test_rule_without_metadata_is_rejected(self):
        _, errors = validate_rule_document(
            {"rules": [{"id": RULE_ID_PREFIX + ".x", "message": "m", "severity": "ERROR",
                        "languages": ["python"], "pattern": "eval(...)"}]}
        )
        self.assertTrue(any("metadata" in e for e in errors))

    def test_rule_without_a_pattern_is_rejected(self):
        _, errors = validate_rule_document(
            {"rules": [{"id": RULE_ID_PREFIX + ".x", "message": "m", "severity": "ERROR",
                        "languages": ["python"],
                        "metadata": {k: "v" for k in REQUIRED_METADATA_FIELDS}}]}
        )
        self.assertTrue(any("pattern" in e for e in errors))

    def test_unnamespaced_rule_id_is_rejected(self):
        _, errors = validate_rule_document(
            {"rules": [{"id": "my-rule", "message": "m", "severity": "ERROR",
                        "languages": ["python"], "pattern": "x",
                        "metadata": {k: "v" for k in REQUIRED_METADATA_FIELDS}}]}
        )
        self.assertTrue(any("must start with" in e for e in errors))

    def test_invalid_severity_is_rejected(self):
        _, errors = validate_rule_document(
            {"rules": [{"id": RULE_ID_PREFIX + ".x", "message": "m", "severity": "CRITICAL",
                        "languages": ["python"], "pattern": "x",
                        "metadata": {k: "v" for k in REQUIRED_METADATA_FIELDS}}]}
        )
        self.assertTrue(any("severity" in e for e in errors))

    def test_non_mapping_document_is_rejected(self):
        self.assertTrue(validate_rule_document(["not", "a", "mapping"])[1])


# --- Language selection ------------------------------------------------------


class LanguageSelection(unittest.TestCase):
    def test_php_project_selects_php_and_common_only(self):
        selection = select_rules(["php"])
        directories = {f.directory for f in selection.selected}
        self.assertIn("php", directories)
        self.assertIn("common", directories)
        self.assertNotIn("csharp", directories)
        self.assertNotIn("python", directories)

    def test_typescript_selects_the_javascript_pack(self):
        self.assertIn("javascript", {f.directory for f in select_rules(["typescript"]).selected})

    def test_kotlin_selects_the_java_pack(self):
        self.assertIn("java", {f.directory for f in select_rules(["kotlin"]).selected})

    def test_common_rules_apply_with_no_language_detected(self):
        self.assertEqual({"common"}, {f.directory for f in select_rules([]).selected})

    def test_unmatched_languages_are_skipped_with_a_reason(self):
        selection = select_rules(["php"])
        self.assertTrue(selection.skipped)
        for _, reason in selection.skipped:
            self.assertTrue(reason)

    def test_skipped_rules_are_counted_not_hidden(self):
        """A rule that exists but did not run is a control that was not exercised."""
        payload = select_rules(["php"]).to_dict()
        self.assertGreater(payload["rules_skipped_count"], 0)
        self.assertGreater(payload["rules_executed_count"], 0)
        self.assertIn("not selected", payload["statement"])

    def test_disabled_pack_reports_unavailable_not_empty_success(self):
        selection = select_rules(["php"], enabled=False)
        self.assertFalse(selection.available)
        self.assertEqual([], selection.config_paths)
        self.assertIn("did NOT run", selection.statement())

    def test_missing_rules_directory_degrades_safely(self):
        selection = select_rules(["php"], rules_root=os.path.join(tempfile.gettempdir(), "nope-xyz"))
        self.assertFalse(selection.available)
        self.assertEqual([], selection.config_paths)


# --- Composition: the invariant that matters --------------------------------


class CompositionIsAdditive(unittest.TestCase):
    def test_project_rules_do_not_remove_the_security_packs(self):
        """THE regression test. Adding a rule must never subtract one."""
        configs, composition = compose_configs(
            base_configs=list(SECURITY_CONFIGS),
            framework_rule_paths=["/rules/php.yml"],
            project_configs=["p/custom-project-rules"],
        )
        for pack in SECURITY_CONFIGS:
            self.assertIn(pack, configs, "%s was lost when project rules were added" % pack)
        self.assertIn("/rules/php.yml", configs)
        self.assertIn("p/custom-project-rules", configs)
        self.assertEqual(composition["mode"], "additive")

    def test_framework_rules_do_not_remove_the_security_packs(self):
        configs, _ = compose_configs(list(SECURITY_CONFIGS), ["/rules/common.yml"], [])
        for pack in SECURITY_CONFIGS:
            self.assertIn(pack, configs)

    def test_default_behaviour_is_unchanged_when_nothing_is_added(self):
        configs, composition = compose_configs(list(SECURITY_CONFIGS), [], [])
        self.assertEqual(configs, list(SECURITY_CONFIGS))
        self.assertEqual(composition["mode"], "additive")
        self.assertEqual(composition["warning"], "")

    def test_duplicate_configs_are_collapsed(self):
        """The same pack twice would run its rules twice and duplicate findings."""
        configs, _ = compose_configs(
            ["p/security-audit", "p/security-audit"], ["/r.yml", "/r.yml"], ["p/security-audit"]
        )
        self.assertEqual(len(configs), len(set(configs)))
        self.assertEqual(configs.count("p/security-audit"), 1)

    def test_ordering_puts_mandatory_packs_first(self):
        configs, _ = compose_configs(["p/security-audit"], ["/r.yml"], ["p/proj"])
        self.assertEqual(configs[0], "p/security-audit")

    def test_replacement_requires_an_explicit_opt_out_and_is_recorded(self):
        configs, composition = compose_configs(
            list(SECURITY_CONFIGS), ["/r.yml"], ["p/only-this"], replace_defaults=True
        )
        self.assertEqual(configs, ["p/only-this"])
        self.assertEqual(composition["mode"], "replace")
        self.assertIn("REPLACED", composition["warning"])
        self.assertIn("did NOT run", composition["warning"])


# --- Collector integration ---------------------------------------------------


class CollectorComposition(unittest.TestCase):
    def setUp(self):
        for var in ("SEMGREP_RULES", "SEMGREP_RULES_REPLACE"):
            os.environ.pop(var, None)

    tearDown = setUp

    def test_default_run_includes_security_packs_and_framework_rules(self):
        collector = SemgrepCollector(languages=["php"])
        for pack in SECURITY_CONFIGS:
            self.assertIn(pack, collector.configs)
        self.assertTrue(any("php" in c for c in collector.composition["framework_rules"]))

    def test_project_override_no_longer_replaces_the_defaults(self):
        """The exact defect this work was commissioned to fix."""
        os.environ["SEMGREP_RULES"] = "p/my-rules"
        collector = SemgrepCollector(languages=["php"])
        self.assertIn("p/my-rules", collector.configs)
        for pack in SECURITY_CONFIGS:
            self.assertIn(pack, collector.configs, "project rules silently removed %s" % pack)

    def test_explicit_replace_opt_out_is_honoured_and_warned(self):
        os.environ["SEMGREP_RULES"] = "p/only-mine"
        os.environ["SEMGREP_RULES_REPLACE"] = "1"
        collector = SemgrepCollector(languages=["php"])
        self.assertEqual(collector.configs, ["p/only-mine"])
        self.assertIn("REPLACED", collector.composition["warning"])

    def test_secure_coding_rules_can_be_disabled_without_losing_security_packs(self):
        collector = SemgrepCollector(languages=["php"], secure_coding_rules=False)
        self.assertEqual([], collector.composition["framework_rules"])
        for pack in SECURITY_CONFIGS:
            self.assertIn(pack, collector.configs)

    def test_rule_selection_is_reported_on_the_result(self):
        collector = SemgrepCollector(languages=["php"])
        result = collector.collect()  # engine absent locally -> fails closed
        self.assertIn("secure_coding_rules", result.metadata)
        self.assertIn("rule_composition", result.metadata)

    def test_missing_engine_is_still_not_verified_with_rules_present(self):
        """Adding our own rules must not change the fail-closed contract."""
        result = SemgrepCollector(languages=["php"], binary="definitely-not-installed").collect()
        self.assertFalse(result.is_trustworthy)
        self.assertTrue(result.errors)

    def test_a_rule_pack_failure_cannot_produce_a_false_pass(self):
        collector = SemgrepCollector(
            languages=["php"], binary="definitely-not-installed", secure_coding_rules=False
        )
        self.assertFalse(collector.collect().is_trustworthy)


if __name__ == "__main__":
    unittest.main()


# --- Fixture coverage --------------------------------------------------------
#
# Rule FIRING is verified in CI by `semgrep --test` against these fixtures --
# Semgrep does not run on the authoring platform, so it cannot be verified here.
# What CAN be verified here is that the fixtures exist and that every rule is
# actually exercised by one. Without this, a rule could ship with no behavioural
# test at all and the CI gate would still pass, because it only checks the
# fixtures that exist.


class FixtureCoverage(unittest.TestCase):
    FIXTURE_EXTENSIONS = {
        "php": ".php", "python": ".py", "javascript": ".js",
        "csharp": ".cs", "java": ".java",
    }

    def _fixture_for(self, rule_file):
        extension = self.FIXTURE_EXTENSIONS.get(rule_file.directory)
        if not extension:
            return None
        return os.path.splitext(rule_file.path)[0] + extension

    def test_every_language_rule_file_has_a_fixture(self):
        for rule_file in discover_rule_files():
            if rule_file.error or rule_file.directory not in self.FIXTURE_EXTENSIONS:
                continue
            fixture = self._fixture_for(rule_file)
            with self.subTest(rules=os.path.basename(rule_file.path)):
                self.assertTrue(
                    os.path.isfile(fixture),
                    "%s has no fixture; its rules would ship with no behavioural test"
                    % os.path.basename(rule_file.path),
                )

    def test_every_rule_is_exercised_by_a_positive_fixture_case(self):
        """A rule with no `ruleid:` annotation is never proven to fire."""
        for rule_file in discover_rule_files():
            if rule_file.error or rule_file.directory not in self.FIXTURE_EXTENSIONS:
                continue
            fixture = self._fixture_for(rule_file)
            if not os.path.isfile(fixture):
                continue
            with open(fixture, "r", encoding="utf-8") as handle:
                body = handle.read()
            for rule_id in rule_file.rule_ids:
                with self.subTest(rule=rule_id):
                    self.assertIn(
                        "ruleid: %s" % rule_id, body,
                        "no vulnerable fixture case asserts that %s fires" % rule_id,
                    )

    def test_every_rule_is_exercised_by_a_negative_fixture_case(self):
        """A rule with no `ok:` annotation is never proven NOT to over-fire.

        This is the half that decides whether developers keep the pack enabled.
        """
        for rule_file in discover_rule_files():
            if rule_file.error or rule_file.directory not in self.FIXTURE_EXTENSIONS:
                continue
            fixture = self._fixture_for(rule_file)
            if not os.path.isfile(fixture):
                continue
            with open(fixture, "r", encoding="utf-8") as handle:
                body = handle.read()
            for rule_id in rule_file.rule_ids:
                with self.subTest(rule=rule_id):
                    self.assertIn(
                        "ok: %s" % rule_id, body,
                        "no safe fixture case asserts that %s stays silent" % rule_id,
                    )


# --- Truthful rule accounting (FD-3) ----------------------------------------
#
# A rule the engine refused to compile did NOT run. The framework previously
# reported every SELECTED rule as executed, so six PHP rules that failed to load
# were still credited with coverage they never provided. These tests hold the
# five figures -- TOTAL / SELECTED / EXECUTED / FAILED_TO_LOAD / SKIPPED -- to
# the rule that EXECUTED must be earned.


class RuleAccounting(unittest.TestCase):
    def _accounting(self, engine_errors, languages=("php",)):
        """Run the collector against a stubbed engine returning `engine_errors`."""
        import json as _json

        from framework.collectors import semgrep as mod

        collector = SemgrepCollector(languages=list(languages))
        selected = collector.rule_selection.rules_executed
        payload = {"results": [], "errors": engine_errors, "paths": {"scanned": []}}

        # Mirrors framework.core.toolrunner.ToolResult closely enough for
        # accepted() -- which checks available/timed_out/error/returncode. Using
        # the real contract rather than a looser stub is deliberate: a stub that
        # diverges would let the test pass while production fails.
        class _Proc:
            available = True
            timed_out = False
            error = ""
            returncode = 0
            stdout = _json.dumps(payload)
            stderr = ""
            duration_seconds = 0.1

            def to_dict(self):
                return {"returncode": 0, "argv": ["semgrep", "scan"], "duration": 0.1}

            def summary(self):
                return "ok"

        original_run, original_avail, original_ver = mod.run, mod.tool_available, mod.tool_version
        mod.run = lambda *a, **k: _Proc()
        mod.tool_available = lambda *a, **k: True
        mod.tool_version = lambda *a, **k: "1.0.0"
        try:
            result = collector.collect()
        finally:
            mod.run, mod.tool_available, mod.tool_version = original_run, original_avail, original_ver
        return result, result.metadata.get("rule_accounting"), selected

    def test_clean_run_credits_every_selected_rule(self):
        result, acc, selected = self._accounting([])
        self.assertEqual(acc["selected"], len(selected))
        self.assertEqual(acc["executed"], len(selected))
        self.assertEqual(acc["failed_to_load"], 0)
        self.assertTrue(result.is_trustworthy)

    def test_total_equals_selected_plus_skipped(self):
        _, acc, _ = self._accounting([])
        self.assertEqual(acc["total"], acc["selected"] + acc["skipped"])

    def test_a_rule_that_fails_to_load_is_not_credited_as_executed(self):
        """THE regression test for false execution credit."""
        _, acc, selected = self._accounting([])
        victim = selected[0]

        _, acc2, _ = self._accounting([
            {"type": "Invalid pattern", "rule_id": victim,
             "message": "Invalid pattern for PHP"}
        ])
        self.assertEqual(acc2["failed_to_load"], 1)
        self.assertEqual(acc2["executed"], acc2["selected"] - 1)
        self.assertNotIn(victim, acc2["executed_rules"])

    def test_failed_rule_is_named_with_its_reason(self):
        _, acc, selected = self._accounting([])
        victim = selected[0]
        _, acc2, _ = self._accounting([
            {"type": "Invalid pattern", "rule_id": victim, "message": "Invalid pattern for PHP"}
        ])
        detail = acc2["failed_to_load_detail"]
        self.assertEqual(detail[0]["rule"], victim)
        self.assertIn("Invalid pattern", detail[0]["reason"])

    def test_rule_load_failure_denies_a_clean_pass(self):
        """A control that never ran must not leave the category trustworthy."""
        _, _, selected = self._accounting([])
        result, _, _ = self._accounting([
            {"type": "Invalid pattern", "rule_id": selected[0], "message": "Invalid pattern for PHP"}
        ])
        self.assertFalse(
            result.is_trustworthy,
            "a framework rule that failed to load costs real coverage; the category "
            "must not be assertable as PASS",
        )
        self.assertTrue(any("FAILED TO LOAD" in w for w in result.warnings))

    def test_six_failed_rules_are_all_accounted(self):
        """The TNCWWB shape: six PHP rules refused by the engine."""
        _, _, selected = self._accounting([])
        victims = selected[:6]
        _, acc, _ = self._accounting([
            {"type": "Invalid pattern", "rule_id": v, "message": "Invalid pattern for PHP"}
            for v in victims
        ])
        self.assertEqual(acc["failed_to_load"], 6)
        self.assertEqual(acc["executed"], acc["selected"] - 6)
        for v in victims:
            self.assertNotIn(v, acc["executed_rules"])

    def test_target_file_parse_errors_do_not_reduce_rule_credit(self):
        """A file the parser could not read is not a rule that failed to load."""
        _, acc, selected = self._accounting([
            {"type": "SyntaxError", "path": "legacy/weird.php", "message": "syntax error"}
        ])
        self.assertEqual(acc["failed_to_load"], 0)
        self.assertEqual(acc["executed"], len(selected))

    def test_engine_never_running_credits_nothing(self):
        collector = SemgrepCollector(languages=["php"], binary="definitely-not-installed")
        result = collector.collect()
        self.assertFalse(result.is_trustworthy)
        self.assertNotIn("rule_accounting", result.metadata)
