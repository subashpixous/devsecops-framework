"""Deployment readiness invariants.

The behaviour this suite exists to pin down, stated once:

    A SECURITY FINDING DOES NOT STOP THE PIPELINE.
    AN UNKNOWN NEVER BECOMES A PASS.

Those two pull in opposite directions and it is easy to satisfy either one alone.
Satisfying the first by suppressing findings, or the second by blocking on every
finding, would both pass a careless test suite. So every case below asserts both
halves: that the run completed and published what it found, AND that nothing it
failed to establish was scored as though it had been.

The matrix covers, by name: a clean project; CRITICAL / HIGH / many findings;
scanner CLEAN / EXECUTED_WITH_FINDINGS / FAILED / NOT_APPLICABLE / NOT_TESTED /
NOT_VERIFIED; incomplete file coverage; parser failure; SonarQube verified and
unverified; build failure; test failure; low coverage; evidence corruption;
mixed scanner states; multiple languages; and each of the four decisions.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional, Sequence

from framework.collectors.base import ScannerResult
from framework.core import readiness as R
from framework.core.categories import (
    CATEGORY_FAILED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_PASS,
    CategoryOutcome,
)
from framework.core.context import RunContext
from framework.core.lifecycle import LifecycleSummary
from framework.core.policy import Policy
from framework.core.schema import Finding
from framework.core.status_engine import StatusEngine

# Categories the bundled policy requires. A FAILED here blocks; a FAILED
# anywhere else is a condition. Read from the policy rather than hard-coded so
# this suite cannot drift from the shipped configuration.
POLICY = Policy.load()
REQUIRED = list(POLICY.required_categories)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def outcome(key: str, status: str, title: str = "", finding_count: int = 0) -> CategoryOutcome:
    return CategoryOutcome(
        key=key,
        title=title or key.replace("_", " ").title(),
        phase=1,
        status=status,
        tools=["tool"],
        reason="constructed for test",
        finding_count=finding_count,
        stage="PRE_BUILD",
    )


def scanner(tool: str, category: str, ok: bool = True, degraded: bool = False,
            errors: Optional[List[str]] = None) -> ScannerResult:
    result = ScannerResult(tool=tool, category_key=category)
    if ok:
        result.succeed()
    else:
        result.fail(errors[0] if errors else "constructed failure")
    if degraded:
        result.degraded = True
    return result


def finding(severity: str, category: str = "vulnerability", scanner_category: str = "sast_semgrep",
            **kwargs: Any) -> Finding:
    base = dict(
        tool="semgrep", rule="r", file="app/x.py", category=category, severity=severity,
        description="a constructed finding", scanner_category=scanner_category,
    )
    base.update(kwargs)
    return Finding(**base)


class FakeAssessment:
    """Only what readiness reads. Keeps a case's intent visible in one place."""

    def __init__(self, categories: Sequence[CategoryOutcome], build_status: str = "UNKNOWN") -> None:
        self.categories = list(categories)
        self.build_status = build_status


def assess(
    categories: Sequence[CategoryOutcome],
    findings: Sequence[Finding] = (),
    scanners: Sequence[ScannerResult] = (),
    file_coverage: Optional[Dict[str, Any]] = None,
    build_status: str = "UNKNOWN",
    test_status: str = "",
    test_coverage: Optional[float] = None,
    import_failures: Optional[Dict[str, str]] = None,
    policy: Optional[Policy] = None,
) -> R.ReadinessAssessment:
    return R.assess(
        policy=policy or Policy.load(),
        assessment=FakeAssessment(categories, build_status),
        findings=list(findings),
        scanner_results=list(scanners),
        file_coverage=file_coverage,
        test_status=test_status,
        test_coverage_percent=test_coverage,
        import_failures=import_failures,
    )


def complete_coverage(percent: float = 100.0) -> Dict[str, Any]:
    return {
        "available": True, "code_files": 100, "code_files_analysed": int(percent),
        "code_files_not_analysed": 100 - int(percent), "coverage_percent": percent,
        "complete": percent >= 100.0, "counts": {}, "statement": "constructed",
    }


def full_pass_categories() -> List[CategoryOutcome]:
    """Every category PASS. The only starting point from which READY is reachable."""
    from framework.core.categories import CATEGORY_REGISTRY
    return [outcome(c.key, CATEGORY_PASS, c.title) for c in CATEGORY_REGISTRY]


def fully_ready_kwargs() -> Dict[str, Any]:
    """The complete set of inputs required for READY, so a case can vary one."""
    return {
        "categories": full_pass_categories(),
        "scanners": [scanner("t%d" % i, c.key) for i, c in enumerate(_registry())],
        "file_coverage": complete_coverage(100.0),
        "build_status": "PASS",
        "test_status": "pass",
        "test_coverage": 100.0,
    }


def _registry():
    from framework.core.categories import CATEGORY_REGISTRY
    return CATEGORY_REGISTRY


# ---------------------------------------------------------------------------
# 1-4. Project states
# ---------------------------------------------------------------------------


class ProjectStates(unittest.TestCase):

    def test_1_completely_clean_project_is_ready(self):
        result = assess(**fully_ready_kwargs())
        self.assertEqual(result.decision, R.DECISION_READY)
        self.assertTrue(result.deployment_permitted)
        self.assertEqual(result.readiness_percent, 100.0)
        self.assertEqual(result.assurance_percent, 100.0)
        self.assertEqual(result.evidence_status, R.EVIDENCE_COMPLETE)
        self.assertFalse(result.blockers)

    def test_2_critical_finding_blocks_but_the_run_still_produced_everything(self):
        kwargs = fully_ready_kwargs()
        kwargs["findings"] = [finding("CRITICAL")]
        result = assess(**kwargs)

        self.assertEqual(result.decision, R.DECISION_NOT_READY)
        self.assertFalse(result.deployment_permitted)
        self.assertTrue(any(b["dimension"] == "finding_risk" for b in result.blockers))
        # The half that matters: the assessment still ran over every dimension.
        # A blocker is a verdict, not a termination.
        self.assertEqual(result.calculation["unknown_dimensions"], 0)
        risk = result.dimension("finding_risk")
        self.assertEqual(risk.evidence["severity_counts"]["CRITICAL"], 1)

    def test_3_high_finding_lowers_readiness_without_blocking(self):
        kwargs = fully_ready_kwargs()
        kwargs["findings"] = [finding("HIGH")]
        result = assess(**kwargs)

        self.assertEqual(result.decision, R.DECISION_CONDITIONALLY_READY)
        self.assertFalse(result.blockers, "a HIGH finding must not block on its own")
        self.assertLess(result.readiness_percent, 100.0)
        self.assertTrue(any(c["dimension"] == "finding_risk" for c in result.conditions))

    def test_4_many_findings_score_worse_than_few(self):
        few = fully_ready_kwargs()
        few["findings"] = [finding("MEDIUM")]
        many = fully_ready_kwargs()
        many["findings"] = [finding("MEDIUM", native_id=str(n)) for n in range(8)]

        self.assertGreater(
            assess(**few).readiness_percent,
            assess(**many).readiness_percent,
            "readiness must distinguish one finding from eight; a category status cannot",
        )

    def test_4b_risk_score_floors_at_zero_rather_than_going_negative(self):
        kwargs = fully_ready_kwargs()
        kwargs["findings"] = [finding("CRITICAL", native_id=str(n)) for n in range(50)]
        result = assess(**kwargs)
        risk = result.dimension("finding_risk")
        self.assertEqual(risk.score, 0.0)
        self.assertGreaterEqual(result.readiness_percent, 0.0)


# ---------------------------------------------------------------------------
# 5-10. Scanner states
# ---------------------------------------------------------------------------


class ScannerStates(unittest.TestCase):

    def test_5_scanner_clean_scores_full_marks(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        self.assertEqual(result.dimension("category:sast_semgrep").state, R.DIM_PASS)
        self.assertEqual(result.dimension("scanner_execution").score, 1.0)

    def test_6_scanner_executed_with_findings_is_not_a_scanner_failure(self):
        """The distinction the whole change rests on."""
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_FAILED)],
            findings=[finding("HIGH")],
            scanners=[scanner("semgrep", "sast_semgrep", ok=True)],
        )
        execution = result.dimension("scanner_execution")
        self.assertEqual(execution.state, R.DIM_PASS)
        self.assertEqual(execution.evidence["not_completed"], 0)
        # The category failed on its findings; the scanner did not fail.
        self.assertEqual(result.dimension("category:sast_semgrep").state, R.DIM_FAILED)
        self.assertIn("completed", execution.statement)

    def test_7_scanner_failed_is_measured_as_a_failure_of_execution(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_NOT_VERIFIED)],
            scanners=[scanner("semgrep", "sast_semgrep", ok=False, errors=["crashed"])],
        )
        execution = result.dimension("scanner_execution")
        self.assertEqual(execution.state, R.DIM_PARTIAL)
        self.assertEqual(execution.evidence["not_completed"], 1)
        # And the category it served is an UNKNOWN, never a pass.
        self.assertEqual(result.dimension("category:sast_semgrep").state, R.DIM_NOT_VERIFIED)
        self.assertIsNone(result.dimension("category:sast_semgrep").score)

    def test_8_not_applicable_leaves_both_sums(self):
        with_na = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS),
                        outcome("container_image", CATEGORY_NOT_APPLICABLE)],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        without = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        self.assertEqual(with_na.readiness_percent, without.readiness_percent)
        self.assertEqual(with_na.assurance_percent, without.assurance_percent)
        self.assertEqual(with_na.dimension("category:container_image").state, R.DIM_NOT_APPLICABLE)
        self.assertGreater(with_na.calculation["excluded_weight"], 0)

    def test_9_not_tested_lowers_assurance_and_scores_nothing(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS),
                        outcome("dast_zap", CATEGORY_NOT_IMPLEMENTED)],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        dast = result.dimension("category:dast_zap")
        self.assertEqual(dast.state, R.DIM_NOT_TESTED)
        self.assertIsNone(dast.score)
        self.assertTrue(dast.unknown)
        self.assertLess(result.assurance_percent, 100.0)

    def test_10_not_verified_lowers_assurance_and_scores_nothing(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS),
                        outcome("sast_sonarqube", CATEGORY_NOT_VERIFIED)],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        sonar = result.dimension("category:sast_sonarqube")
        self.assertEqual(sonar.state, R.DIM_NOT_VERIFIED)
        self.assertIsNone(sonar.score)
        self.assertLess(result.assurance_percent, 100.0)

    def test_19_mixed_scanner_states_are_each_reported_on_their_own_terms(self):
        result = assess(
            categories=[
                outcome("sast_semgrep", CATEGORY_PASS),
                outcome("secret_scanning", CATEGORY_FAILED),
                outcome("sca_dependencies", CATEGORY_NOT_VERIFIED),
                outcome("container_image", CATEGORY_NOT_APPLICABLE),
                outcome("dast_zap", CATEGORY_NOT_IMPLEMENTED),
            ],
            scanners=[
                scanner("semgrep", "sast_semgrep"),
                scanner("gitleaks", "secret_scanning"),
                scanner("trivy", "sca_dependencies", ok=False, errors=["timeout"]),
            ],
        )
        states = {d.key: d.state for d in result.dimensions}
        self.assertEqual(states["category:sast_semgrep"], R.DIM_PASS)
        self.assertEqual(states["category:secret_scanning"], R.DIM_FAILED)
        self.assertEqual(states["category:sca_dependencies"], R.DIM_NOT_VERIFIED)
        self.assertEqual(states["category:container_image"], R.DIM_NOT_APPLICABLE)
        self.assertEqual(states["category:dast_zap"], R.DIM_NOT_TESTED)
        # Five different conditions, five different states. Nothing collapsed
        # into a shared bucket, which is the failure mode this guards against.
        category_states = {v for k, v in states.items() if k.startswith("category:")}
        self.assertEqual(len(category_states), 5, category_states)


# ---------------------------------------------------------------------------
# 11-14. Coverage, parsing, external analysis
# ---------------------------------------------------------------------------


class CoverageAndAnalysis(unittest.TestCase):

    def test_11_incomplete_file_coverage_scores_the_measured_fraction(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
            file_coverage=complete_coverage(62.0),
        )
        coverage = result.dimension("code_coverage")
        self.assertEqual(coverage.state, R.DIM_PARTIAL)
        self.assertAlmostEqual(coverage.score, 0.62)
        self.assertEqual(result.evidence_status, R.EVIDENCE_INCOMPLETE)

    def test_12_a_census_that_did_not_run_is_unknown_not_full_coverage(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
            file_coverage={"available": False, "reason": "parser failure"},
        )
        coverage = result.dimension("code_coverage")
        self.assertEqual(coverage.state, R.DIM_NOT_VERIFIED)
        self.assertIsNone(coverage.score)
        self.assertIn("UNKNOWN", coverage.statement)

    def test_12b_a_workspace_with_no_code_is_not_applicable_not_zero_coverage(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
            file_coverage={"available": True, "code_files": 0, "code_files_analysed": 0,
                           "coverage_percent": 0.0, "complete": False},
        )
        self.assertEqual(result.dimension("code_coverage").state, R.DIM_NOT_APPLICABLE)

    def test_13_sonarqube_verified_scores(self):
        result = assess(
            categories=[outcome("sast_sonarqube", CATEGORY_PASS)],
            scanners=[scanner("sonarqube", "sast_sonarqube")],
        )
        self.assertEqual(result.dimension("category:sast_sonarqube").score, 1.0)

    def test_14_sonarqube_not_verified_never_scores(self):
        result = assess(
            categories=[outcome("sast_sonarqube", CATEGORY_NOT_VERIFIED)],
            scanners=[scanner("sonarqube", "sast_sonarqube", ok=False, errors=["stale analysis"])],
        )
        self.assertIsNone(result.dimension("category:sast_sonarqube").score)
        self.assertNotEqual(result.decision, R.DECISION_READY)


# ---------------------------------------------------------------------------
# 15-18. Delivery signals and evidence integrity
# ---------------------------------------------------------------------------


class DeliveryAndIntegrity(unittest.TestCase):

    def test_15_build_failure_blocks(self):
        kwargs = fully_ready_kwargs()
        kwargs["build_status"] = "FAIL"
        result = assess(**kwargs)
        self.assertEqual(result.decision, R.DECISION_NOT_READY)
        self.assertTrue(any(b["dimension"] == "build" for b in result.blockers))

    def test_15b_an_unreported_build_is_not_a_passing_build(self):
        kwargs = fully_ready_kwargs()
        kwargs["build_status"] = "UNKNOWN"
        result = assess(**kwargs)
        build = result.dimension("build")
        self.assertEqual(build.state, R.DIM_NOT_REPORTED)
        self.assertIsNone(build.score)
        self.assertNotEqual(result.decision, R.DECISION_READY)

    def test_16_unit_test_failure_blocks(self):
        kwargs = fully_ready_kwargs()
        kwargs["test_status"] = "failed"
        result = assess(**kwargs)
        self.assertEqual(result.decision, R.DECISION_NOT_READY)
        self.assertTrue(any(b["dimension"] == "unit_tests" for b in result.blockers))

    def test_16b_tests_that_did_not_run_are_not_tests_that_passed(self):
        kwargs = fully_ready_kwargs()
        kwargs["test_status"] = "skipped"
        result = assess(**kwargs)
        self.assertEqual(result.dimension("unit_tests").state, R.DIM_NOT_TESTED)
        self.assertIsNone(result.dimension("unit_tests").score)

    def test_17_low_test_coverage_lowers_readiness_without_blocking(self):
        kwargs = fully_ready_kwargs()
        kwargs["test_coverage"] = 31.0
        result = assess(**kwargs)
        coverage = result.dimension("test_coverage")
        self.assertAlmostEqual(coverage.score, 0.31)
        self.assertFalse(coverage.blocking)
        self.assertLess(result.readiness_percent, 100.0)

    def test_17b_an_unparseable_coverage_figure_is_not_reported_not_zero(self):
        for value in ("", "n/a", "-1", "101", None):
            self.assertIsNone(R.parse_coverage_percent(value), value)
        self.assertEqual(R.parse_coverage_percent("84.2"), 84.2)
        self.assertEqual(R.parse_coverage_percent("77%"), 77.0)

    def test_18_evidence_corruption_forces_unknown_and_blocks(self):
        """A category claiming PASS on a scanner that did not complete."""
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep", ok=False, errors=["crashed"])],
            file_coverage=complete_coverage(100.0),
            build_status="PASS", test_status="pass", test_coverage=100.0,
        )
        self.assertEqual(result.evidence_status, R.EVIDENCE_UNTRUSTWORTHY)
        self.assertEqual(result.decision, R.DECISION_UNKNOWN)
        self.assertFalse(result.deployment_permitted)
        self.assertTrue(result.integrity_problems)

    def test_18b_a_scanner_that_is_ok_and_degraded_is_a_contradiction(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_NOT_VERIFIED)],
            scanners=[scanner("semgrep", "sast_semgrep", ok=True, degraded=True)],
        )
        self.assertEqual(result.evidence_status, R.EVIDENCE_UNTRUSTWORTHY)
        self.assertTrue(
            any("OK while also recording a degradation" in p for p in result.integrity_problems)
        )

    def test_18c_findings_with_no_recorded_execution_are_a_contradiction(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            findings=[finding("HIGH", scanner_category="ghost_category")],
            scanners=[scanner("semgrep", "sast_semgrep")],
        )
        self.assertEqual(result.evidence_status, R.EVIDENCE_UNTRUSTWORTHY)
        self.assertTrue(any("ghost_category" in p for p in result.integrity_problems))

    def test_18d_a_collector_that_failed_to_import_degrades_without_contradicting(self):
        result = assess(
            categories=[outcome("sast_semgrep", CATEGORY_PASS)],
            scanners=[scanner("semgrep", "sast_semgrep")],
            import_failures={"trivy": "ImportError: no module"},
        )
        integrity = result.dimension("evidence_integrity")
        self.assertEqual(integrity.state, R.DIM_PARTIAL)
        self.assertFalse(integrity.blocking)
        self.assertNotEqual(result.evidence_status, R.EVIDENCE_UNTRUSTWORTHY)
        self.assertTrue(any("trivy" in p for p in result.integrity_problems))


class Governance(unittest.TestCase):
    """Accepted risk that stopped being reviewed is a blocker, not a footnote."""

    def test_an_expired_suppression_blocks_deployment(self):
        kwargs = fully_ready_kwargs()
        kwargs["categories"] = [
            outcome(c.key, CATEGORY_FAILED if c.key == "finding_lifecycle" else CATEGORY_PASS,
                    c.title)
            for c in _registry()
        ]
        result = assess(**kwargs)
        self.assertEqual(result.decision, R.DECISION_NOT_READY)
        self.assertTrue(
            any(b["dimension"] == "category:finding_lifecycle" for b in result.blockers),
            "an expired suppression must block; the shipped policy lists it as blocking",
        )

    def test_a_missing_baseline_does_not_block(self):
        """NOT_VERIFIED is an unknown. Unknowns lower assurance; they never block."""
        kwargs = fully_ready_kwargs()
        kwargs["categories"] = [
            outcome(c.key,
                    CATEGORY_NOT_VERIFIED if c.key == "finding_lifecycle" else CATEGORY_PASS,
                    c.title)
            for c in _registry()
        ]
        result = assess(**kwargs)
        self.assertFalse(result.blockers)
        self.assertEqual(result.decision, R.DECISION_CONDITIONALLY_READY)
        self.assertLess(result.assurance_percent, 100.0)

    def test_a_valid_suppression_still_removes_a_finding_from_the_risk_score(self):
        suppressed = finding("CRITICAL")
        suppressed.lifecycle = "ACCEPTED_RISK"
        suppressed.exception_expires = "2099-01-01"
        kwargs = dict(fully_ready_kwargs(), findings=[suppressed])
        result = assess(**kwargs)
        risk = result.dimension("finding_risk")
        self.assertEqual(risk.evidence["open_security_findings"], 0)
        self.assertFalse(risk.blocking)

    def test_a_non_security_finding_category_does_not_drive_the_risk_score(self):
        """Bugs and code smells are collected and reported; they are not risk."""
        kwargs = dict(fully_ready_kwargs(),
                      findings=[finding("CRITICAL", category="bug")])
        result = assess(**kwargs)
        self.assertEqual(result.dimension("finding_risk").evidence["risk_points"], 0)


# ---------------------------------------------------------------------------
# 20. Multiple projects / languages -- adaptivity
# ---------------------------------------------------------------------------


class ProjectAdaptivity(unittest.TestCase):

    def test_20_dimensions_are_derived_from_the_registry_not_hard_coded(self):
        from framework.core.categories import CATEGORY_REGISTRY
        result = assess(categories=full_pass_categories(),
                        scanners=[scanner("t", c.key) for c in CATEGORY_REGISTRY])
        keys = {d.key for d in result.dimensions}
        for category in CATEGORY_REGISTRY:
            self.assertIn("category:%s" % category.key, keys,
                          "category %s produced no readiness dimension" % category.key)

    def test_20b_a_project_with_fewer_applicable_categories_can_still_reach_ready(self):
        """A static-only PHP project and a containerised one must both be assessable."""
        from framework.core.categories import CATEGORY_REGISTRY
        categories = []
        for category in CATEGORY_REGISTRY:
            if category.applies_when in ("docker", "kubernetes", "iac", "openapi",
                                         "package_manager_or_docker", "cloud", "cloud_aws"):
                categories.append(outcome(category.key, CATEGORY_NOT_APPLICABLE, category.title))
            else:
                categories.append(outcome(category.key, CATEGORY_PASS, category.title))
        result = assess(
            categories=categories,
            scanners=[scanner("t%d" % i, c.key) for i, c in enumerate(CATEGORY_REGISTRY)],
            file_coverage=complete_coverage(100.0),
            build_status="PASS", test_status="pass", test_coverage=100.0,
        )
        self.assertEqual(result.decision, R.DECISION_READY)
        self.assertEqual(result.assurance_percent, 100.0)

    def test_20c_no_project_name_language_or_path_appears_in_the_module(self):
        import framework.core.readiness as module
        with open(module.__file__, encoding="utf-8") as handle:
            source = handle.read().lower()
        for token in ("tncwwb", "pixous", "oneportal", "dashboard-v2v", "sonarqube.example"):
            self.assertNotIn(token, source, "a project identifier leaked into the readiness model")


# ---------------------------------------------------------------------------
# 21-24. The four decisions
# ---------------------------------------------------------------------------


class Decisions(unittest.TestCase):

    def test_21_ready(self):
        self.assertEqual(assess(**fully_ready_kwargs()).decision, R.DECISION_READY)

    def test_22_conditionally_ready(self):
        kwargs = fully_ready_kwargs()
        kwargs["file_coverage"] = complete_coverage(90.0)
        result = assess(**kwargs)
        self.assertEqual(result.decision, R.DECISION_CONDITIONALLY_READY)
        self.assertFalse(
            result.deployment_permitted,
            "the shipped policy must not let CONDITIONALLY_READY authorise deployment by itself",
        )

    def test_23_not_ready(self):
        kwargs = fully_ready_kwargs()
        kwargs["findings"] = [finding("CRITICAL")]
        self.assertEqual(assess(**kwargs).decision, R.DECISION_NOT_READY)

    def test_24_unknown_when_too_little_was_measured(self):
        result = assess(
            categories=[outcome(c.key, CATEGORY_NOT_VERIFIED, c.title) for c in _registry()],
        )
        self.assertEqual(result.decision, R.DECISION_UNKNOWN)
        self.assertFalse(result.deployment_permitted)

    def test_24b_unknown_when_nothing_at_all_was_measured(self):
        result = assess(categories=[], file_coverage={"available": False, "reason": "none"})
        self.assertIn(result.decision, (R.DECISION_UNKNOWN,))
        self.assertFalse(result.deployment_permitted)

    def test_every_decision_carries_a_rationale(self):
        cases = [
            fully_ready_kwargs(),
            dict(fully_ready_kwargs(), file_coverage=complete_coverage(90.0)),
            dict(fully_ready_kwargs(), findings=[finding("CRITICAL")]),
            dict(categories=[outcome(c.key, CATEGORY_NOT_VERIFIED) for c in _registry()]),
        ]
        seen = set()
        for kwargs in cases:
            result = assess(**kwargs)
            seen.add(result.decision)
            self.assertTrue(result.decision_rationale, result.decision)
            self.assertTrue(result.statement, result.decision)
        self.assertEqual(seen, set(R.DECISIONS), "the matrix must exercise all four decisions")

    def test_conditionally_ready_can_authorise_deployment_only_by_explicit_policy(self):
        permissive = Policy.load()
        permissive.conditionally_ready_permits_deployment = True
        kwargs = dict(fully_ready_kwargs(), file_coverage=complete_coverage(90.0))
        result = assess(policy=permissive, **kwargs)
        self.assertEqual(result.decision, R.DECISION_CONDITIONALLY_READY)
        self.assertTrue(result.deployment_permitted)


# ---------------------------------------------------------------------------
# The two headline invariants
# ---------------------------------------------------------------------------


class HeadlineInvariants(unittest.TestCase):

    def test_a_security_finding_never_reduces_what_was_assessed(self):
        """Findings change the verdict. They must not shrink the evidence set."""
        clean = assess(**fully_ready_kwargs())
        dirty = assess(**dict(fully_ready_kwargs(),
                              findings=[finding(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]))

        self.assertEqual(len(clean.dimensions), len(dirty.dimensions))
        self.assertEqual(clean.assurance_percent, dirty.assurance_percent)
        self.assertEqual(
            clean.calculation["unknown_dimensions"], dirty.calculation["unknown_dimensions"],
            "finding vulnerabilities must not turn any dimension into an unknown",
        )

    def test_no_unknown_state_can_ever_produce_a_score(self):
        for state in R.UNKNOWN_STATES:
            dimension = R.ReadinessDimension(
                key="k", title="t", family=R.FAMILY_ASSURANCE, state=state, weight=5.0,
                score=1.0,  # a caller trying to score an unknown
            )
            self.assertEqual(
                dimension.earned, 0.0,
                "state %s earned weight despite never having been measured" % state,
            )
            self.assertFalse(dimension.measured)

    def test_readiness_is_recomputable_from_the_published_dimension_table(self):
        result = assess(**dict(fully_ready_kwargs(),
                               file_coverage=complete_coverage(70.0),
                               findings=[finding("MEDIUM")]))
        published = result.to_dict()
        measured = [d for d in published["dimensions"] if d["counts_toward_score"]]
        unknown = [d for d in published["dimensions"] if d["counts_toward_unknown"]]

        earned = sum(d["earned"] for d in measured)
        weight = sum(d["weight"] for d in measured)
        unknown_weight = sum(d["weight"] for d in unknown)

        self.assertAlmostEqual(round(100.0 * earned / weight, 1), published["readiness_percent"], 1)
        self.assertAlmostEqual(
            round(100.0 * weight / (weight + unknown_weight), 1),
            published["assurance_percent"], 1,
        )

    def test_readiness_never_raises_whatever_it_is_handed(self):
        """A broken readiness assessment must degrade to UNKNOWN, not kill the run."""
        class Exploding:
            @property
            def categories(self):
                raise RuntimeError("constructed failure")

        result = R.assess(
            policy=Policy.load(), assessment=Exploding(), findings=[], scanner_results=[],
        )
        self.assertEqual(result.decision, R.DECISION_UNKNOWN)
        self.assertFalse(result.deployment_permitted)
        self.assertTrue(result.integrity_problems)


# ---------------------------------------------------------------------------
# Integration with the real status engine
# ---------------------------------------------------------------------------


class StatusEngineIntegration(unittest.TestCase):
    """Readiness must never disagree with the verdict it was computed beside."""

    def _run(self, results, findings, capabilities=None):
        policy = Policy.load()
        engine = StatusEngine(policy)
        context = RunContext(framework_version="test", build_status_input="pass")
        assessment = engine.evaluate(
            context=context,
            capabilities=capabilities or {"languages": ["python"], "package_manager": ["pip"]},
            scanner_results=results,
            findings=findings,
            lifecycle=LifecycleSummary(baseline_available=True, baseline_source="test"),
            stages=["PRE_BUILD", "POST_BUILD", "AGGREGATION", "POST_DEPLOY", "CLOUD"],
        )
        readiness = R.assess(
            policy=policy, assessment=assessment, findings=findings, scanner_results=results,
            file_coverage=complete_coverage(100.0), test_status="pass", test_coverage_percent=100.0,
        )
        return assessment, readiness

    def test_a_failed_category_appears_in_both_the_verdict_and_readiness(self):
        results = [scanner("semgrep", "sast_semgrep")]
        findings = [finding("HIGH")]
        assessment, readiness = self._run(results, findings)

        self.assertEqual(assessment.security_status, "FAILED")
        # Same fact, two vocabularies, no disagreement.
        self.assertEqual(readiness.dimension("category:sast_semgrep").state, R.DIM_FAILED)
        self.assertNotEqual(readiness.decision, R.DECISION_READY)

    def test_open_finding_counts_agree_between_the_engine_and_readiness(self):
        findings = [finding(s, native_id=str(n)) for n, s in enumerate(("HIGH", "HIGH", "MEDIUM"))]
        results = [scanner("semgrep", "sast_semgrep")]
        assessment, readiness = self._run(results, findings)
        risk = readiness.dimension("finding_risk")
        for severity, count in assessment.security_severity_counts.items():
            self.assertEqual(
                risk.evidence["severity_counts"].get(severity, 0), count,
                "readiness and the status engine disagree about open %s findings" % severity,
            )


if __name__ == "__main__":
    unittest.main()
