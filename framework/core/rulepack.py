"""Framework-owned secure-coding rule pack: discovery, validation, composition.

WHY THIS EXISTS
---------------
Until now this framework owned no detection content at all. Every finding came
from someone else's rules -- SonarQube's, Semgrep's registry, Checkov's. That is
fine for breadth and useless for the patterns that are specific to how an
application leaks information rather than to a language primitive:

    return ex.Message;              // hands the database error to the attacker
    DEBUG = True                    // in a production settings file
    catch (e) { res.send(e.stack) } // stack trace as an API response

Generic packs under-serve these because they are framework-shaped rather than
language-shaped, and because a rule that fires on every `catch` block is worse
than no rule. They are, however, exactly the patterns a security reviewer looks
for first.

WHAT THIS MODULE DOES -- AND DOES NOT DO
----------------------------------------
It does NOT implement a matching engine. Writing one would mean competing with
Semgrep on its own ground with a fraction of the effort behind it, and producing
a worse result. The rules here are Semgrep-format YAML, executed by whichever
engine is already installed. The framework owns the CONTENT; the engine stays
someone else's problem.

A useful consequence: the same YAML runs under Opengrep, whose rule licensing
carries none of the restrictions the Semgrep registry now does.

COMPOSITION IS ADDITIVE
-----------------------
The registry security packs are mandatory and cannot be removed by configuration.
A project may ADD rules; it may only replace the defaults by setting an explicit
opt-out, and that choice is recorded on the result. This matters because the
previous behaviour -- `SEMGREP_RULES` replacing the whole configuration -- meant
that adding one custom rule silently switched off `p/security-audit` and
`p/owasp-top-ten`. A coverage loss disguised as a coverage gain is precisely the
failure this framework exists to make impossible.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Rules live beside the framework package so they ship with it.
RULES_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

# Directory name -> the detected languages that make that directory applicable.
# A directory with no mapping never runs: silence is better than findings in a
# language the rule was not written for.
LANGUAGE_DIRECTORIES: Dict[str, Tuple[str, ...]] = {
    "common": (),  # empty tuple == always applicable
    "csharp": ("csharp",),
    "python": ("python",),
    "javascript": ("javascript", "typescript", "vue", "svelte"),
    "php": ("php",),
    "java": ("java", "kotlin"),
}

# Every rule must declare these. A rule without them cannot be triaged, cannot be
# mapped to a control, and cannot be justified to an auditor.
REQUIRED_RULE_FIELDS = ("id", "message", "severity", "languages")
REQUIRED_METADATA_FIELDS = ("category", "cwe", "confidence", "rationale", "remediation")

VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}
VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}

# Rule ids are namespaced so a finding's origin is unambiguous in a report that
# also carries registry and SonarQube findings.
RULE_ID_PREFIX = "devsecops-framework.secure-coding"


@dataclass
class RuleFile:
    """One YAML file of rules, with the languages that make it applicable."""

    path: str
    directory: str
    applicable_languages: Tuple[str, ...]
    rule_ids: Tuple[str, ...] = ()
    error: str = ""

    @property
    def always_applicable(self) -> bool:
        return self.applicable_languages == ()

    def applies_to(self, detected: Sequence[str]) -> bool:
        if self.always_applicable:
            return True
        lowered = {str(language).lower() for language in detected or ()}
        return bool(lowered & set(self.applicable_languages))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": os.path.basename(self.path),
            "directory": self.directory,
            "applicable_languages": list(self.applicable_languages) or "all",
            "rule_count": len(self.rule_ids),
            "rule_ids": list(self.rule_ids),
            "error": self.error,
        }


@dataclass
class RulePackSelection:
    """Which framework rules will run this time, and which will not -- and why.

    The `skipped` list is not bookkeeping. A rule that exists but did not run is
    a control that was not exercised, and the coverage census has to be able to
    say so rather than let the reader assume every rule fired.
    """

    selected: List[RuleFile] = field(default_factory=list)
    skipped: List[Tuple[RuleFile, str]] = field(default_factory=list)
    invalid: List[RuleFile] = field(default_factory=list)
    detected_languages: Tuple[str, ...] = ()
    available: bool = True
    reason: str = ""

    @property
    def config_paths(self) -> List[str]:
        return [rule_file.path for rule_file in self.selected]

    @property
    def rules_executed(self) -> List[str]:
        return sorted(rid for rule_file in self.selected for rid in rule_file.rule_ids)

    @property
    def rules_skipped(self) -> List[str]:
        return sorted(rid for rule_file, _ in self.skipped for rid in rule_file.rule_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "detected_languages": list(self.detected_languages),
            "files_selected": [rule_file.to_dict() for rule_file in self.selected],
            "files_skipped": [
                dict(rule_file.to_dict(), skip_reason=reason) for rule_file, reason in self.skipped
            ],
            "files_invalid": [rule_file.to_dict() for rule_file in self.invalid],
            "rules_executed_count": len(self.rules_executed),
            "rules_skipped_count": len(self.rules_skipped),
            "rules_executed": self.rules_executed,
            "rules_skipped": self.rules_skipped,
            "statement": self.statement(),
        }

    def statement(self) -> str:
        if not self.available:
            return (
                "The framework secure-coding rule pack did NOT run: %s. No rule in the pack was "
                "applied to this project." % (self.reason or "reason not recorded")
            )
        if not self.selected:
            return (
                "No framework secure-coding rule applied to this project. Detected languages "
                "(%s) match none of the rule directories, so this pack contributed nothing. "
                "That is not a statement that the code is free of these patterns."
                % (", ".join(self.detected_languages) or "none detected")
            )
        # "Selected", not "applied". Selection happens here; execution happens in
        # the engine, and only the scanner result can say whether it completed.
        # Reporting selection as application would let a failed scan read as a
        # clean one.
        return (
            "%d framework secure-coding rule(s) from %d file(s) were SELECTED for detected "
            "language(s) %s. %d rule(s) in the pack were not selected because no detected "
            "language matched them. Whether the selected rules actually ran is determined by "
            "the engine's own execution status, reported separately."
            % (
                len(self.rules_executed), len(self.selected),
                ", ".join(self.detected_languages) or "none",
                len(self.rules_skipped),
            )
        )


def _load_yaml(path: str) -> Any:
    import yaml  # local import: PyYAML is a declared dependency but not needed at import time

    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def validate_rule_document(document: Any) -> Tuple[List[str], List[str]]:
    """Validate one rule file. Returns (rule_ids, errors).

    Validation is strict on purpose. A malformed rule file makes the whole
    Semgrep invocation fail, which would take the entire SAST category down with
    it -- so a broken framework rule must be caught here, by our own tests,
    rather than on a consumer's runner.
    """
    errors: List[str] = []
    if not isinstance(document, dict):
        return [], ["rule file must contain a mapping at the top level"]

    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        return [], ["rule file declares no 'rules' list"]

    rule_ids: List[str] = []
    for index, rule in enumerate(rules):
        label = "rule[%d]" % index
        if not isinstance(rule, dict):
            errors.append("%s is not a mapping" % label)
            continue

        rule_id = rule.get("id")
        if isinstance(rule_id, str) and rule_id:
            label = rule_id
            rule_ids.append(rule_id)
            if not rule_id.startswith(RULE_ID_PREFIX):
                errors.append(
                    "%s: id must start with %r so a finding's origin is unambiguous"
                    % (label, RULE_ID_PREFIX)
                )

        for field_name in REQUIRED_RULE_FIELDS:
            if not rule.get(field_name):
                errors.append("%s: missing required field %r" % (label, field_name))

        severity = rule.get("severity")
        if severity and severity not in VALID_SEVERITIES:
            errors.append(
                "%s: severity %r is not one of %s" % (label, severity, sorted(VALID_SEVERITIES))
            )

        languages = rule.get("languages")
        if languages is not None and not isinstance(languages, list):
            errors.append("%s: 'languages' must be a list" % label)

        # A rule must actually match something.
        if not any(key in rule for key in ("pattern", "patterns", "pattern-either", "pattern-regex")):
            errors.append("%s: declares no pattern, patterns, pattern-either or pattern-regex" % label)

        metadata = rule.get("metadata")
        if not isinstance(metadata, dict):
            errors.append("%s: missing 'metadata' block" % label)
            continue

        for field_name in REQUIRED_METADATA_FIELDS:
            if not metadata.get(field_name):
                errors.append(
                    "%s: metadata.%s is required -- a rule that cannot be justified to a "
                    "reviewer should not ship" % (label, field_name)
                )

        confidence = metadata.get("confidence")
        if confidence and str(confidence).upper() not in VALID_CONFIDENCE:
            errors.append(
                "%s: metadata.confidence %r is not one of %s"
                % (label, confidence, sorted(VALID_CONFIDENCE))
            )

    return rule_ids, errors


def discover_rule_files(rules_root: str = RULES_ROOT) -> List[RuleFile]:
    """Find every rule file the framework ships, validated.

    Never raises. A rule pack that cannot be read must degrade to "no framework
    rules ran", which is a reported gap -- not an exception that takes down the
    SAST category.
    """
    discovered: List[RuleFile] = []
    if not os.path.isdir(rules_root):
        return discovered

    for directory in sorted(os.listdir(rules_root)):
        directory_path = os.path.join(rules_root, directory)
        if not os.path.isdir(directory_path):
            continue

        applicable = LANGUAGE_DIRECTORIES.get(directory)
        if applicable is None:
            # An undeclared directory never runs. Executing rules against
            # languages nobody mapped is how false findings reach a report.
            discovered.append(
                RuleFile(
                    path=directory_path, directory=directory, applicable_languages=("__unmapped__",),
                    error="directory %r is not declared in LANGUAGE_DIRECTORIES; its rules never run"
                          % directory,
                )
            )
            continue

        for filename in sorted(os.listdir(directory_path)):
            if not filename.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(directory_path, filename)
            rule_file = RuleFile(path=path, directory=directory, applicable_languages=applicable)
            try:
                document = _load_yaml(path)
            except Exception as exc:  # noqa: BLE001 - a broken rule file is data, not a crash
                rule_file.error = "could not be parsed: %s: %s" % (type(exc).__name__, exc)
                discovered.append(rule_file)
                continue

            rule_ids, errors = validate_rule_document(document)
            rule_file.rule_ids = tuple(rule_ids)
            if errors:
                rule_file.error = "; ".join(errors)
            discovered.append(rule_file)

    return discovered


def select_rules(
    detected_languages: Sequence[str] = (),
    rules_root: str = RULES_ROOT,
    enabled: bool = True,
) -> RulePackSelection:
    """Choose the framework rules applicable to this project.

    A rule file runs only when a detected language maps to its directory, or
    when it is language-independent (`common/`). Everything else is skipped WITH
    A REASON, so the report can distinguish "checked and clean" from "never
    checked".
    """
    selection = RulePackSelection(detected_languages=tuple(str(l).lower() for l in detected_languages or ()))

    if not enabled:
        selection.available = False
        selection.reason = "disabled by configuration"
        return selection

    if not os.path.isdir(rules_root):
        selection.available = False
        selection.reason = "the rule pack directory %s does not exist" % rules_root
        return selection

    for rule_file in discover_rule_files(rules_root):
        if rule_file.error:
            # An invalid rule file is never handed to the engine: one malformed
            # file fails the whole scan, which would convert a rule-authoring
            # mistake into a lost SAST category.
            selection.invalid.append(rule_file)
            continue
        if not rule_file.rule_ids:
            selection.skipped.append((rule_file, "file declares no rules"))
            continue
        if rule_file.applies_to(selection.detected_languages):
            selection.selected.append(rule_file)
        else:
            selection.skipped.append(
                (
                    rule_file,
                    "no detected language matches this rule set (requires one of: %s)"
                    % ", ".join(rule_file.applicable_languages),
                )
            )

    return selection


def compose_configs(
    base_configs: Sequence[str],
    framework_rule_paths: Sequence[str] = (),
    project_configs: Sequence[str] = (),
    replace_defaults: bool = False,
) -> Tuple[List[str], Dict[str, Any]]:
    """Build the final engine configuration. ADDITIVE unless explicitly told not to be.

    Returns (configs, composition_record). The record travels onto the
    ScannerResult so a reader can see exactly which rule sources were combined,
    and whether the mandatory security packs were in force.

    `replace_defaults` exists because a project genuinely may need to pin its own
    ruleset -- but it is an explicit, recorded decision, never the silent side
    effect of adding one custom rule.
    """
    base = [c for c in base_configs if c]
    framework = [p for p in framework_rule_paths if p]
    project = [c for c in project_configs if c]

    if replace_defaults:
        configs = list(project) or list(base)
        composition = {
            "mode": "replace",
            "base_security_packs": [] if project else base,
            "framework_rules": [],
            "project_configs": project,
            "warning": (
                "Default security packs were REPLACED by project configuration. The registry "
                "security and OWASP packs did NOT run in this scan. This was an explicit "
                "opt-out, and coverage is correspondingly narrower."
            ),
        }
        return configs, composition

    # De-duplicate while preserving order: base first so the mandatory packs are
    # unambiguously present, then framework rules, then project additions.
    seen: Set[str] = set()
    configs: List[str] = []
    for config in list(base) + list(framework) + list(project):
        if config not in seen:
            seen.add(config)
            configs.append(config)

    composition = {
        "mode": "additive",
        "base_security_packs": base,
        "framework_rules": framework,
        "project_configs": project,
        "warning": "",
    }
    return configs, composition


def rule_inventory(rules_root: str = RULES_ROOT) -> Dict[str, Any]:
    """Everything the pack contains, for documentation and tests."""
    files = discover_rule_files(rules_root)
    valid = [f for f in files if not f.error]
    invalid = [f for f in files if f.error]
    by_directory: Dict[str, List[str]] = {}
    for rule_file in valid:
        by_directory.setdefault(rule_file.directory, []).extend(rule_file.rule_ids)
    return {
        "rules_root": rules_root,
        "total_files": len(files),
        "valid_files": len(valid),
        "invalid_files": [dict(f.to_dict(), error=f.error) for f in invalid],
        "total_rules": sum(len(f.rule_ids) for f in valid),
        "by_directory": {k: sorted(v) for k, v in sorted(by_directory.items())},
    }
