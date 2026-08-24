"""Status engine invariants.

These tests encode the non-negotiable rules of the framework. If any of them
fails, the framework must not be released: a false PASS is worse than no report.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.collectors.base import ScannerResult  # noqa: E402
from framework.core.categories import (  # noqa: E402
    CATEGORY_FAILED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_PASS,
    CATEGORY_REGISTRY,
    CATEGORY_STATUSES,
    DEPLOYMENT_DEPLOYED,
    DEPLOYMENT_FAILED,
    RUNTIME_NOT_TESTED,
    SCANNER_FAILED,
    SCANNER_OK,
    SCANNER_PARTIAL,
    SECURITY_FAILED,
    SECURITY_NOT_VERIFIED,
    SECURITY_PASS,
)
from framework.core.context import RunContext  # noqa: E402
from framework.core.policy import Policy  # noqa: E402
from framework.core.schema import Finding  # noqa: E402
from framework.core.status_engine import StatusEngine  # noqa: E402

CAPABILITIES = {
    "languages": ["typescript"],
    "frameworks": ["angular"],
    "package_manager": ["npm"],
    "docker": True,
    "iac": False,
    "kubernetes": False,
    "openapi": False,
    "frontend": True,
    "backend": True,
    "cloud": "aws",
    "deployment_target": "ssh-host-docker-compose",
    "deployed_url": "",
    "authenticated_testing_available": False,
}

GATE_OK = {"status": "OK", "conditions": [], "failing_conditions": []}
GATE_ERROR = {
    "status": "ERROR",
    "conditions": [{"metric": "new_security_rating", "status": "ERROR"}],
    "failing_conditions": [{"metric": "new_security_rating", "status": "ERROR"}],
}


def ok_result():
    result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
    result.payload = {"issues": []}
    return result.succeed().finish()


def failed_result(message="server unreachable"):
    result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
    return result.fail(message).finish()


def partial_result(message="hotspots unavailable"):
    result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
    result.payload = {"issues": []}
    return result.partial(message).finish()


def vulnerability(severity="CRITICAL"):
    return Finding(
        tool="sonarqube",
        category="vulnerability",
        severity=severity,
        file="src/app.ts",
        line=10,
        description="Hard-coded credential",
        rule="typescript:S2068",
        scanner_category="sast_sonarqube",
        status="OPEN",
    )


class StatusEngineTestCase(unittest.TestCase):
    def setUp(self):
        # These tests exercise the ENGINE, not the shipped policy. Pinning a
        # narrow policy keeps each assertion about one rule; the shipped default
        # is covered separately by DefaultPolicyTestCase.
        self.policy = Policy.load()
        self.policy.required_categories = ["sast_sonarqube"]
        self.policy.active_phase = 1
        self.engine = StatusEngine(self.policy)
        self.context = RunContext(project_name="p", commit="abc123", branch="main")

    def evaluate(self, results, findings=None, gate=None, context=None):
        return self.engine.evaluate(
            context=context or self.context,
            capabilities=CAPABILITIES,
            scanner_results=results,
            findings=findings or [],
            quality_gate=gate if gate is not None else GATE_OK,
        )

    # --- The core invariant: no false PASS -----------------------------------

    def test_scanner_failure_yields_not_verified_never_pass(self):
        assessment = self.evaluate([failed_result()])
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)
        self.assertNotEqual(assessment.security_status, SECURITY_PASS)

    def test_missing_scanner_result_yields_not_verified(self):
        assessment = self.evaluate([])
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)

    def test_partial_scan_yields_not_verified(self):
        assessment = self.evaluate([partial_result()])
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)

    def test_malformed_payload_yields_not_verified(self):
        result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
        result.fail("malformed JSON").finish()
        assessment = self.evaluate([result])
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)

    def test_scanner_failure_with_zero_findings_is_still_not_verified(self):
        """Zero findings from a broken scanner must never read as clean."""
        assessment = self.evaluate([failed_result()], findings=[])
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)

    # --- Deployment independence ---------------------------------------------

    def test_successful_deployment_does_not_raise_security_status(self):
        context = RunContext(deployment_status_input="deployed", build_status_input="pass")
        assessment = self.evaluate([failed_result()], context=context)
        self.assertEqual(assessment.deployment_status, DEPLOYMENT_DEPLOYED)
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)

    def test_failed_deployment_does_not_lower_security_status(self):
        context = RunContext(deployment_status_input="failed", build_status_input="pass")
        assessment = self.evaluate([ok_result()], context=context)
        self.assertEqual(assessment.deployment_status, DEPLOYMENT_FAILED)
        self.assertEqual(assessment.security_status, SECURITY_PASS)

    def test_security_failure_does_not_change_deployment_status(self):
        context = RunContext(deployment_status_input="deployed")
        assessment = self.evaluate([ok_result()], findings=[vulnerability()], context=context)
        self.assertEqual(assessment.security_status, SECURITY_FAILED)
        self.assertEqual(assessment.deployment_status, DEPLOYMENT_DEPLOYED)

    def test_all_four_statuses_are_independent_combination_is_representable(self):
        context = RunContext(build_status_input="pass", deployment_status_input="deployed")
        assessment = self.evaluate([ok_result()], findings=[vulnerability()], context=context)
        self.assertEqual(assessment.build_status, "PASS")
        self.assertEqual(assessment.deployment_status, DEPLOYMENT_DEPLOYED)
        self.assertEqual(assessment.security_status, SECURITY_FAILED)
        self.assertEqual(assessment.runtime_security_status, RUNTIME_NOT_TESTED)

    # --- Failure conditions ---------------------------------------------------

    def test_threshold_breach_yields_failed(self):
        assessment = self.evaluate([ok_result()], findings=[vulnerability("CRITICAL")])
        self.assertEqual(assessment.security_status, SECURITY_FAILED)
        self.assertTrue(assessment.threshold_breaches)

    def test_quality_gate_error_yields_failed(self):
        assessment = self.evaluate([ok_result()], gate=GATE_ERROR)
        self.assertEqual(assessment.security_status, SECURITY_FAILED)

    def test_unknown_severity_fails_closed(self):
        finding = vulnerability("something-unrecognised")
        self.assertEqual(finding.severity, "UNKNOWN")
        assessment = self.evaluate([ok_result()], findings=[finding])
        self.assertEqual(assessment.security_status, SECURITY_FAILED)

    def test_medium_severity_does_not_fail_by_default(self):
        assessment = self.evaluate([ok_result()], findings=[vulnerability("MEDIUM")])
        self.assertEqual(assessment.security_status, SECURITY_PASS)

    def test_resolved_findings_do_not_count(self):
        finding = vulnerability("CRITICAL")
        finding.status = "RESOLVED"
        assessment = self.evaluate([ok_result()], findings=[finding])
        self.assertEqual(assessment.security_status, SECURITY_PASS)

    def test_code_smells_do_not_fail_the_security_verdict(self):
        smell = Finding(
            tool="sonarqube", category="code_smell", severity="CRITICAL", file="a.ts",
            description="smell", scanner_category="sast_sonarqube",
        )
        assessment = self.evaluate([ok_result()], findings=[smell])
        self.assertEqual(assessment.security_status, SECURITY_PASS)

    def test_hotspots_excluded_from_thresholds_by_default_but_reported(self):
        hotspot = Finding(
            tool="sonarqube", category="security_hotspot", severity="HIGH", file="a.ts",
            description="hotspot", scanner_category="sast_sonarqube", status="TO_REVIEW",
        )
        assessment = self.evaluate([ok_result()], findings=[hotspot])
        self.assertEqual(assessment.security_status, SECURITY_PASS)
        self.assertEqual(assessment.security_severity_counts["HIGH"], 1)

    def test_failed_takes_precedence_but_unverified_still_listed(self):
        results = [ok_result()]
        assessment = self.evaluate(results, findings=[vulnerability()], gate=GATE_ERROR)
        self.assertEqual(assessment.security_status, SECURITY_FAILED)
        self.assertTrue(any("FAILED" in line for line in assessment.rationale))

    # --- No silent gaps -------------------------------------------------------

    def test_every_registered_category_resolves_to_a_known_status(self):
        assessment = self.evaluate([ok_result()])
        self.assertEqual(len(assessment.categories), len(CATEGORY_REGISTRY))
        for outcome in assessment.categories:
            self.assertIn(outcome.status, CATEGORY_STATUSES)

    def test_future_phase_categories_are_not_implemented_not_pass(self):
        assessment = self.evaluate([ok_result()])
        by_key = {c.key: c for c in assessment.categories}
        for key in ("secret_scanning", "sca_dependencies", "dast_zap", "cloud_posture"):
            self.assertEqual(by_key[key].status, CATEGORY_NOT_IMPLEMENTED, key)

    def test_inapplicable_categories_are_not_applicable(self):
        assessment = self.evaluate([ok_result()])
        by_key = {c.key: c for c in assessment.categories}
        self.assertEqual(by_key["iac_scanning"].status, CATEGORY_NOT_APPLICABLE)
        self.assertEqual(by_key["kubernetes_security"].status, CATEGORY_NOT_APPLICABLE)
        self.assertEqual(by_key["api_spec_security"].status, CATEGORY_NOT_APPLICABLE)

    def test_coverage_is_never_reported_complete_in_phase_one(self):
        assessment = self.evaluate([ok_result()])
        self.assertFalse(assessment.coverage_complete)

    def test_pass_verdict_carries_explicit_scope(self):
        assessment = self.evaluate([ok_result()])
        self.assertEqual(assessment.security_status, SECURITY_PASS)
        self.assertTrue(assessment.verdict_scope.startswith("PHASE_1["))
        self.assertIn("sast_sonarqube", assessment.verdict_scope)

    def test_runtime_security_is_not_tested_in_phase_one(self):
        assessment = self.evaluate([ok_result()])
        self.assertEqual(assessment.runtime_security_status, RUNTIME_NOT_TESTED)

    def test_unknown_deployed_url_keeps_dast_applicable_with_a_blocking_note(self):
        assessment = self.evaluate([ok_result()])
        dast = next(c for c in assessment.categories if c.key == "dast_zap")
        self.assertEqual(dast.status, CATEGORY_NOT_IMPLEMENTED)
        self.assertTrue(any("deployed_url" in note for note in dast.notes))

    def test_limitations_always_include_manual_controls(self):
        assessment = self.evaluate([ok_result()])
        codes = {item["code"] for item in assessment.limitations}
        self.assertIn("MANUAL_CONTROLS_NOT_AUTOMATED", codes)
        self.assertIn("PHASE_SCOPE_INCOMPLETE", codes)
        self.assertEqual(len(assessment.manual_controls), 11)

    def test_language_coverage_gap_is_reported(self):
        capabilities = dict(CAPABILITIES, languages=["typescript", "csharp"])
        assessment = self.engine.evaluate(
            context=self.context,
            capabilities=capabilities,
            scanner_results=[ok_result()],
            findings=[vulnerability("LOW")],  # a .ts finding only
            quality_gate=GATE_OK,
        )
        codes = {item["code"] for item in assessment.limitations}
        self.assertIn("SAST_LANGUAGE_COVERAGE_UNCONFIRMED", codes)
        detail = next(i["detail"] for i in assessment.limitations if i["code"] == "SAST_LANGUAGE_COVERAGE_UNCONFIRMED")
        self.assertIn("csharp", detail)

    def test_build_status_unknown_when_not_reported(self):
        assessment = self.evaluate([ok_result()])
        self.assertEqual(assessment.build_status, "UNKNOWN")

    def test_scanner_errors_surface_in_limitations(self):
        assessment = self.evaluate([failed_result("token rejected")])
        details = " ".join(i["detail"] for i in assessment.limitations)
        self.assertIn("token rejected", details)


class DefaultPolicyTestCase(unittest.TestCase):
    """The shipped default policy, as configured for production use."""

    def setUp(self):
        self.policy = Policy.load()

    def test_all_phases_are_active_by_default(self):
        # Asserted against the category registry rather than a literal. The
        # invariant is "the shipped policy leaves no declared category sitting at
        # NOT_IMPLEMENTED", which a hard-coded 6 stops expressing the moment a
        # phase 7 category is added -- it then fails for the one reason that is
        # not a defect.
        highest = max(category.phase for category in CATEGORY_REGISTRY)
        self.assertEqual(
            self.policy.active_phase, highest,
            "default policy active_phase (%d) must cover the highest declared category "
            "phase (%d), otherwise shipped categories report NOT_IMPLEMENTED"
            % (self.policy.active_phase, highest),
        )

    def test_required_categories_cover_the_always_applicable_sast_and_secrets(self):
        for key in ("sast_sonarqube", "sast_semgrep", "secret_scanning"):
            self.assertIn(key, self.policy.required_categories)

    def test_every_scanner_finding_category_is_security_relevant(self):
        for category in ("secret", "dependency_vulnerability", "container_vulnerability",
                         "misconfiguration", "cloud_misconfiguration", "dast_finding",
                         "sast_finding", "supply_chain", "tls", "cors"):
            self.assertTrue(
                self.policy.is_security_finding_category(category),
                "%s must count toward the security verdict" % category,
            )

    def test_severe_thresholds_fail_closed(self):
        for level in ("CRITICAL", "HIGH", "UNKNOWN"):
            self.assertEqual(self.policy.threshold_for(level), 0)

    def test_missing_required_scanner_under_default_policy_is_not_verified(self):
        """With three required categories, one passing scanner is not enough."""
        engine = StatusEngine(self.policy)
        assessment = engine.evaluate(
            context=RunContext(),
            capabilities=CAPABILITIES,
            scanner_results=[ok_result()],   # sonarqube only
            findings=[],
            quality_gate=GATE_OK,
        )
        self.assertEqual(assessment.security_status, SECURITY_NOT_VERIFIED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
