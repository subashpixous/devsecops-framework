"""Regression tests for finding routing and scanner-error classification.

Two defects motivated these:

  1. Checkov filed every result under `iac_scanning`. On a project with no IaC
     that category is NOT_APPLICABLE, so committed-secret and container findings
     were reported but carried no verdict weight at all.

  2. Semgrep treated ANY entry in `errors` as lost coverage, so a single file the
     parser could not read pushed the whole SAST category to NOT_VERIFIED and
     every real finding stopped gating.

Both fixes must make the framework MORE accurate without ever making PASS easier
to reach, so the fail-closed direction is asserted explicitly in each case.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.adapters.checkov_adapter import (  # noqa: E402
    CheckovDockerfileAdapter,
    CheckovIacAdapter,
    CheckovSecretsAdapter,
    build_adapter,
)
from framework.collectors.base import ScannerResult  # noqa: E402
from framework.collectors.checkov import _strip_secret_material  # noqa: E402
from framework.collectors.semgrep import _classify_errors  # noqa: E402
from framework.core.categories import CATEGORY_BY_KEY  # noqa: E402
from framework.core.context import RunContext  # noqa: E402

CTX = RunContext(environment="test", branch="main", commit="0" * 40)


def result_for(category_key, payload, tool="checkov"):
    r = ScannerResult(tool=tool, category_key=category_key)
    r.payload = payload
    return r


def check(check_id, path="/main.tf", **extra):
    base = {
        "check_id": check_id,
        "check_name": "example check",
        "file_path": path,
        "file_line_range": [10, 20],
        "resource": "res-1",
        "guideline": "https://example/docs",
    }
    base.update(extra)
    return base


class CheckovRoutingTestCase(unittest.TestCase):
    def test_secret_checks_route_to_secret_scanning(self):
        payload = {"failed_checks": [check("CKV_SECRET_6", "/appsettings.json")]}
        findings = CheckovSecretsAdapter().normalize(
            result_for("secret_scanning", payload), CTX
        )
        self.assertEqual(findings[0].scanner_category, "secret_scanning")
        self.assertEqual(findings[0].category, "secret")
        self.assertEqual(findings[0].cwe, "CWE-798")

    def test_dockerfile_checks_route_to_container_hardening(self):
        payload = {"failed_checks": [check("CKV_DOCKER_3", "/Dockerfile")]}
        findings = CheckovDockerfileAdapter().normalize(
            result_for("container_hardening", payload), CTX
        )
        self.assertEqual(findings[0].scanner_category, "container_hardening")
        self.assertEqual(findings[0].category, "misconfiguration")

    def test_iac_checks_still_route_to_iac_scanning(self):
        payload = {"failed_checks": [check("CKV_AWS_18")]}
        findings = CheckovIacAdapter().normalize(result_for("iac_scanning", payload), CTX)
        self.assertEqual(findings[0].scanner_category, "iac_scanning")
        self.assertEqual(findings[0].category, "misconfiguration")

    def test_container_hardening_category_is_declared_and_applicable_on_docker(self):
        cat = CATEGORY_BY_KEY["container_hardening"]
        self.assertEqual(cat.stage, "PRE_BUILD")
        self.assertEqual(cat.applies_when, "docker")

    def test_secret_component_is_the_file_not_the_value_hash(self):
        # Checkov puts a hash of the matched value in `resource` for secret checks.
        # Using it as the component would hide which files are affected.
        payload = {"failed_checks": [
            check("CKV_SECRET_6", "/appsettings.json", resource="a" * 40)
        ]}
        f = CheckovSecretsAdapter().normalize(result_for("secret_scanning", payload), CTX)[0]
        self.assertEqual(f.component, "/appsettings.json")
        self.assertNotIn("a" * 40, f.component)

    def test_severity_and_evidence_are_preserved(self):
        payload = {"failed_checks": [check("CKV_DOCKER_2", "/Dockerfile", severity="HIGH")]}
        f = CheckovDockerfileAdapter().normalize(
            result_for("container_hardening", payload), CTX
        )[0]
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.line, 10)
        self.assertIn("/Dockerfile", f.evidence)
        self.assertIn("CKV_DOCKER_2", f.evidence)

    def test_absent_severity_still_fails_closed_to_unknown(self):
        payload = {"failed_checks": [check("CKV_DOCKER_3", "/Dockerfile")]}
        f = build_adapter("container").normalize(
            result_for("container_hardening", payload), CTX
        )[0]
        self.assertEqual(f.severity, "UNKNOWN")

    def test_no_finding_is_dropped_by_routing(self):
        payload = {"failed_checks": [
            check("CKV_SECRET_6", "/a.json"),
            check("CKV_SECRET_1", "/b.json"),
            check("CKV_DOCKER_3", "/Dockerfile"),
        ]}
        self.assertEqual(
            len(CheckovSecretsAdapter().normalize(result_for("secret_scanning", payload), CTX)),
            3,
        )


class CheckovSecretHygieneTestCase(unittest.TestCase):
    def test_collector_strips_secret_bearing_fields(self):
        raw = check("CKV_SECRET_6", code_block=[[1, "password = 'hunter2'"]])
        cleaned = _strip_secret_material(raw)
        self.assertIsNone(cleaned["code_block"])
        self.assertIn("code_block", cleaned["_redacted_fields"])

    def test_adapter_refuses_a_record_that_still_carries_secret_material(self):
        # Defence in depth: if stripping ever regresses, the adapter must fail the
        # result rather than publish a credential into a downloadable artifact.
        payload = {"failed_checks": [
            check("CKV_SECRET_6", code_block=[[1, "password = 'hunter2'"]])
        ]}
        result = result_for("secret_scanning", payload)
        findings = CheckovSecretsAdapter().normalize(result, CTX)
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "FAILED")
        self.assertTrue(result.degraded)

    def test_no_secret_value_reaches_the_finding(self):
        raw = check("CKV_SECRET_6", code_block=[[1, "password = 'hunter2'"]])
        payload = {"failed_checks": [_strip_secret_material(raw)]}
        f = CheckovSecretsAdapter().normalize(result_for("secret_scanning", payload), CTX)[0]
        blob = " ".join(str(v) for v in f.to_dict().values())
        self.assertNotIn("hunter2", blob)


class FingerprintCollisionTestCase(unittest.TestCase):
    """One exception must never suppress several independent findings.

    Measured on a real project, 83 of 156 findings shared an identity across 21
    groups, so a single exception entry would have silenced up to 11 unrelated
    findings at once.
    """

    def finding(self, **kw):
        from framework.core.schema import Finding

        base = dict(
            tool="gitleaks", rule="generic-api-key", file="appsettings.json",
            category="secret", description="Detected a Generic API Key",
            severity="CRITICAL", native_id="", line=0, component="",
        )
        base.update(kw)
        return Finding(**base)

    def test_same_rule_on_different_lines_of_one_file_are_distinct(self):
        a = self.finding(line=10)
        b = self.finding(line=40)
        c = self.finding(line=116)
        self.assertEqual(len({a.fingerprint, b.fingerprint, c.fingerprint}), 3)

    def test_one_cve_affecting_two_packages_is_two_findings(self):
        # Same file, same line (0), same native id -- only the component differs.
        a = self.finding(tool="trivy", rule="CVE-2026-22610", category="dependency_vulnerability",
                         file="package-lock.json", native_id="CVE-2026-22610",
                         component="@angular/compiler@16.2.12")
        b = self.finding(tool="trivy", rule="CVE-2026-22610", category="dependency_vulnerability",
                         file="package-lock.json", native_id="CVE-2026-22610",
                         component="@angular/core@16.2.12")
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_repeated_rule_hits_in_one_file_are_distinct(self):
        a = self.finding(tool="semgrep", rule="csharp-sqli", category="sast_finding",
                         file="MySqlHelper.cs", line=135)
        b = self.finding(tool="semgrep", rule="csharp-sqli", category="sast_finding",
                         file="MySqlHelper.cs", line=185)
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_the_same_finding_is_still_stable_across_runs(self):
        # Uniqueness must not cost idempotence: identical input, identical id.
        a = self.finding(line=10, native_id="n1", component="c1")
        b = self.finding(line=10, native_id="n1", component="c1")
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_description_normalisation_still_applies(self):
        a = self.finding(description="Hard-coded password", line=1)
        b = self.finding(description="  hard-coded   PASSWORD ", line=1)
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_line_type_does_not_change_identity(self):
        self.assertEqual(self.finding(line=10).fingerprint,
                         self.finding(line="10").fingerprint)

    def test_checkov_secret_native_id_is_per_occurrence_not_per_rule(self):
        payload = {"failed_checks": [
            check("CKV_SECRET_6", "/appsettings.json", resource="a" * 40, file_line_range=[10, 11]),
            check("CKV_SECRET_6", "/appsettings.json", resource="b" * 40, file_line_range=[40, 41]),
        ]}
        f1, f2 = CheckovSecretsAdapter().normalize(result_for("secret_scanning", payload), CTX)
        self.assertNotEqual(f1.native_id, f2.native_id)
        self.assertNotEqual(f1.fingerprint, f2.fingerprint)

    def test_checkov_dockerfile_native_id_is_per_occurrence(self):
        payload = {"failed_checks": [
            check("CKV_DOCKER_3", "/API/Dockerfile"),
            check("CKV_DOCKER_3", "/UI/Dockerfile"),
        ]}
        f1, f2 = CheckovDockerfileAdapter().normalize(
            result_for("container_hardening", payload), CTX)
        self.assertNotEqual(f1.fingerprint, f2.fingerprint)


class ExceptionCannotCollideTestCase(unittest.TestCase):
    """The consequence the collision actually had: over-suppression.

    Before the fix, one exception for `generic-api-key` in `appsettings.DEV.json`
    would have suppressed five different credentials in that file.
    """

    def secrets_in_one_file(self, lines):
        from framework.core.schema import Finding

        return [
            Finding(
                tool="gitleaks", rule="generic-api-key", file="appsettings.DEV.json",
                category="secret", description="Detected a Generic API Key",
                severity="CRITICAL", line=ln,
                native_id="c0ffee:appsettings.DEV.json:generic-api-key:%d" % ln,
            )
            for ln in lines
        ]

    def test_an_exception_suppresses_exactly_one_finding(self):
        from framework.core.lifecycle import Exception_, apply_lifecycle, is_suppressed

        findings = self.secrets_in_one_file([10, 40, 116, 118, 120])
        self.assertEqual(len({f.fingerprint for f in findings}), 5, "fingerprints collided")

        target = findings[2]
        exceptions = {
            target.fingerprint: Exception_(
                target.fingerprint, "accepted_risk",
                reason="reviewed", expires="2999-01-01",
            )
        }
        apply_lifecycle(findings, {}, "", exceptions, "exc.yml", {"secret_scanning"})

        suppressed = [f for f in findings if is_suppressed(f)]
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0].line, 116)
        self.assertEqual(len([f for f in findings if not is_suppressed(f)]), 4)


class SemgrepErrorClassificationTestCase(unittest.TestCase):
    def parse_error(self, path):
        return {"type": "Syntax error", "level": "warn",
                "message": "Syntax error at line %s:1" % path, "path": path}

    def test_named_parse_error_is_a_bounded_gap_not_a_blocking_failure(self):
        blocking, unparsed = _classify_errors([self.parse_error("/w/a.component.html")])
        self.assertEqual(blocking, [])
        self.assertEqual(unparsed, {"a.component.html"})

    def test_rule_error_is_blocking(self):
        err = {"type": "PatternParseError", "level": "error", "message": "bad rule",
               "rule_id": "x.y.z"}
        blocking, unparsed = _classify_errors([err])
        self.assertEqual(len(blocking), 1)
        self.assertEqual(unparsed, set())

    def test_unattributable_parse_error_fails_closed_as_blocking(self):
        # A parse error that does not name a file bounds nothing, so it must not be
        # downgraded to a coverage note.
        blocking, unparsed = _classify_errors([{"type": "Syntax error", "level": "warn"}])
        self.assertEqual(len(blocking), 1)
        self.assertEqual(unparsed, set())

    def test_mixed_errors_split_correctly(self):
        errs = [self.parse_error("/w/a.html"),
                {"type": "PatternParseError", "message": "bad rule"},
                self.parse_error("/w/b.html")]
        blocking, unparsed = _classify_errors(errs)
        self.assertEqual(len(blocking), 1)
        self.assertEqual(unparsed, {"a.html", "b.html"})


class SemgrepCollectorDegradationTestCase(unittest.TestCase):
    """The collector's use of the classification, which is where trust is decided."""

    def _run_with(self, payload):
        import json as _json
        from unittest import mock

        from framework.collectors import semgrep as mod

        proc = mock.Mock()
        proc.stdout = _json.dumps(payload)
        proc.returncode = 0
        proc.to_dict.return_value = {}
        with mock.patch.object(mod, "tool_available", return_value=True), \
             mock.patch.object(mod, "tool_version", return_value="1.0"), \
             mock.patch.object(mod, "run", return_value=proc), \
             mock.patch.object(mod, "accepted", return_value=True):
            return mod.SemgrepCollector(workspace=".").collect()

    def parse_error(self, path):
        return {"type": "Syntax error", "level": "warn",
                "message": "Syntax error at line %s:1" % path, "path": path}

    def test_parse_gap_with_real_findings_still_reports_ok(self):
        # The whole point of the fix: real findings must keep gating.
        result = self._run_with({
            "results": [{"check_id": "x", "path": "a.cs"}],
            "errors": [self.parse_error("/w/t.component.html")],
        })
        self.assertEqual(result.status, "OK")
        self.assertFalse(result.degraded)
        self.assertTrue(result.is_trustworthy)
        self.assertTrue(any("NOT analysed" in w for w in result.warnings))
        self.assertEqual(result.metadata["unparsed_files"], ["t.component.html"])

    def test_parse_gap_with_no_findings_fails_closed(self):
        # "Clean" cannot be trusted while files went unread.
        result = self._run_with({
            "results": [],
            "errors": [self.parse_error("/w/t.component.html")],
        })
        self.assertEqual(result.status, "PARTIAL")
        self.assertTrue(result.degraded)
        self.assertFalse(result.is_trustworthy)

    def test_blocking_error_still_degrades_even_with_findings(self):
        result = self._run_with({
            "results": [{"check_id": "x", "path": "a.cs"}],
            "errors": [{"type": "PatternParseError", "message": "bad rule"}],
        })
        self.assertEqual(result.status, "PARTIAL")
        self.assertTrue(result.degraded)
        self.assertFalse(result.is_trustworthy)

    def test_clean_scan_with_no_errors_is_ok(self):
        result = self._run_with({"results": [], "errors": []})
        self.assertEqual(result.status, "OK")
        self.assertFalse(result.degraded)


class ScannerWarnTestCase(unittest.TestCase):
    def test_warn_records_the_caveat_without_degrading(self):
        r = ScannerResult(tool="t", category_key="c")
        r.warn("3 files could not be parsed")
        r.succeed()
        self.assertEqual(r.status, "OK")
        self.assertFalse(r.degraded)
        self.assertIn("3 files could not be parsed", r.warnings[0])

    def test_warn_never_overrides_a_recorded_degradation(self):
        r = ScannerResult(tool="t", category_key="c")
        r.partial("real coverage loss")
        r.warn("also this")
        r.succeed()
        self.assertEqual(r.status, "PARTIAL")
        self.assertTrue(r.degraded)
        self.assertFalse(r.is_trustworthy)

    def test_warn_does_not_make_a_failed_result_trustworthy(self):
        r = ScannerResult(tool="t", category_key="c")
        r.fail("scanner exploded")
        r.warn("note")
        r.succeed()
        self.assertEqual(r.status, "FAILED")
        self.assertFalse(r.is_trustworthy)


if __name__ == "__main__":
    unittest.main()
