"""Deployment readiness: what the evidence supports, as distinct from what was found.

WHY THIS EXISTS
---------------
The status engine answers "did the security controls pass". That question has
exactly one honest answer and the framework already gives it. It is the wrong
question to gate a pipeline on, and gating on it produced the failure this
module fixes: a consumer with nothing better to key on writes
`if SECURITY != PASS: exit 1`, the pipeline dies at the first finding, and every
later stage -- the remaining scanners, the evidence pack, the report -- never
runs. The finding is then LESS visible, not more.

Readiness answers a different question: given everything this run established,
and everything it failed to establish, how much of the deployment picture is
actually supported by evidence, and should this thing ship?

SIX INDEPENDENT OUTPUTS
-----------------------
Nothing here derives one from another:

    PIPELINE    did the framework produce a complete evidence set
    SECURITY    the security verdict (owned by status_engine, untouched)
    EVIDENCE    is the evidence complete, incomplete, or self-contradictory
    READINESS   percent of MEASURED weight that passed
    ASSURANCE   percent of total weight that was measured at all
    DECISION    READY / CONDITIONALLY_READY / NOT_READY / UNKNOWN

THE ONE RULE THAT MAKES THE NUMBER HONEST
-----------------------------------------
An unmeasured dimension earns nothing and is not silently dropped. It leaves
the readiness numerator AND denominator, and its weight moves to
`unknown_weight`, which drives `assurance_percent`. So a run that tested one
thing and passed it reports:

    readiness 100%  assurance 8%

and can never reach READY. There is no arrangement of NOT_TESTED, NOT_VERIFIED
or SCANNER_FAILED states that produces a high assurance figure, which is the
whole point: "we did not look" must not be able to masquerade as "we looked and
it was fine".

NOT_APPLICABLE is the one state that leaves both sums. A project with no
Dockerfile is not penalised for having no container findings, and is not
credited for it either.

EVERY NUMBER IS REPRODUCIBLE
----------------------------
Each dimension publishes its state, its weight, its score and the evidence it
was computed from. `calculation` publishes the sums and the formula. A reader
can recompute the percentage by hand from the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .categories import (
    BUILD_FAIL,
    BUILD_PASS,
    CATEGORY_FAILED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_PASS,
)
from .lifecycle import is_suppressed
from .schema import SEVERITY_CRITICAL, SEVERITY_ORDER, Finding, severity_breakdown

# --- Dimension states --------------------------------------------------------
#
# Deliberately NOT the same vocabulary as category status. A category status
# describes a control; a dimension state describes what this run established
# about one facet of deployability, and the two differ in exactly the places
# that matter -- NOT_REPORTED has no category equivalent, and PARTIAL carries a
# fractional score no category status can express.

DIM_PASS = "PASS"
DIM_FAILED = "FAILED"
DIM_PARTIAL = "PARTIAL"
DIM_NOT_APPLICABLE = "NOT_APPLICABLE"
DIM_NOT_VERIFIED = "NOT_VERIFIED"
DIM_NOT_TESTED = "NOT_TESTED"
DIM_NOT_REPORTED = "NOT_REPORTED"

# States that carry a number. Only these contribute to the readiness percentage.
MEASURED_STATES = frozenset((DIM_PASS, DIM_FAILED, DIM_PARTIAL))
# States that mean "this run did not establish it". These NEVER score. They are
# counted separately so the report can say how much of the picture is missing.
UNKNOWN_STATES = frozenset((DIM_NOT_VERIFIED, DIM_NOT_TESTED, DIM_NOT_REPORTED))
# The one state that leaves both sums. Absence of a Dockerfile is not a gap.
EXCLUDED_STATES = frozenset((DIM_NOT_APPLICABLE,))

DIMENSION_STATES = tuple(sorted(MEASURED_STATES | UNKNOWN_STATES | EXCLUDED_STATES))

# --- Families ----------------------------------------------------------------

FAMILY_DELIVERY = "DELIVERY"
FAMILY_SECURITY = "SECURITY_VALIDATION"
FAMILY_ASSURANCE = "ASSURANCE"

FAMILIES = (FAMILY_DELIVERY, FAMILY_SECURITY, FAMILY_ASSURANCE)

# --- Deployment decision -----------------------------------------------------

DECISION_READY = "READY"
DECISION_CONDITIONALLY_READY = "CONDITIONALLY_READY"
DECISION_NOT_READY = "NOT_READY"
DECISION_UNKNOWN = "UNKNOWN"

DECISIONS = (
    DECISION_READY,
    DECISION_CONDITIONALLY_READY,
    DECISION_NOT_READY,
    DECISION_UNKNOWN,
)

# --- Pipeline execution status ----------------------------------------------
#
# Whether the FRAMEWORK completed, not whether the application is good. This is
# the only one of the six that a CI exit code should ever track by default.

PIPELINE_COMPLETED = "COMPLETED"
PIPELINE_COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
PIPELINE_INCOMPLETE = "INCOMPLETE"

PIPELINE_STATUSES = (
    PIPELINE_COMPLETED,
    PIPELINE_COMPLETED_WITH_ERRORS,
    PIPELINE_INCOMPLETE,
)

# --- Evidence completeness ---------------------------------------------------

EVIDENCE_COMPLETE = "COMPLETE"
EVIDENCE_INCOMPLETE = "INCOMPLETE"
EVIDENCE_UNTRUSTWORTHY = "UNTRUSTWORTHY"

EVIDENCE_STATUSES = (EVIDENCE_COMPLETE, EVIDENCE_INCOMPLETE, EVIDENCE_UNTRUSTWORTHY)


def normalise_test_status(value: str) -> str:
    """Caller-reported unit-test result -> a dimension state.

    Nothing is inferred. An unrecognised or empty value is NOT_REPORTED, which
    is an unknown and therefore scores nothing. It is never read as success.
    """
    token = (value or "").strip().lower()
    if token in ("pass", "passed", "success", "succeeded", "true", "ok", "green"):
        return DIM_PASS
    if token in ("fail", "failed", "failure", "false", "error", "red"):
        return DIM_FAILED
    if token in ("skipped", "skip", "no_tests", "none", "not_tested", "cancelled"):
        return DIM_NOT_TESTED
    return DIM_NOT_REPORTED


def parse_coverage_percent(value: Any) -> Optional[float]:
    """Caller-reported coverage figure -> a float, or None for NOT_REPORTED.

    Returns None for anything that is not a number in [0, 100]. A negative
    sentinel, an empty string and an unparseable value all mean the same thing:
    nobody reported a figure, and none is invented.
    """
    if value is None:
        return None
    text = str(value).strip().rstrip("%")
    if not text:
        return None
    try:
        number = float(text)
    except (TypeError, ValueError):
        return None
    if number < 0 or number > 100:
        return None
    return number


@dataclass
class ReadinessDimension:
    """One measurable facet of deployability."""

    key: str
    title: str
    family: str
    state: str
    weight: float
    # None whenever the state is not a measured one. Deliberately not 0.0:
    # "scored zero" and "never scored" must not render identically.
    score: Optional[float] = None
    statement: str = ""
    blocking: bool = False
    blocking_reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def measured(self) -> bool:
        return self.state in MEASURED_STATES

    @property
    def unknown(self) -> bool:
        return self.state in UNKNOWN_STATES

    @property
    def excluded(self) -> bool:
        return self.state in EXCLUDED_STATES

    @property
    def earned(self) -> float:
        return (self.score or 0.0) * self.weight if self.measured else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "family": self.family,
            "state": self.state,
            "weight": self.weight,
            "score": self.score,
            "earned": round(self.earned, 4) if self.measured else None,
            "counts_toward_score": self.measured,
            "counts_toward_unknown": self.unknown,
            "blocking": self.blocking,
            "blocking_reason": self.blocking_reason,
            "statement": self.statement,
            "evidence": self.evidence,
        }


@dataclass
class ReadinessAssessment:
    """The complete readiness picture for one run."""

    dimensions: List[ReadinessDimension] = field(default_factory=list)
    readiness_percent: float = 0.0
    assurance_percent: float = 0.0
    decision: str = DECISION_UNKNOWN
    deployment_permitted: bool = False
    evidence_status: str = EVIDENCE_UNTRUSTWORTHY
    blockers: List[Dict[str, str]] = field(default_factory=list)
    conditions: List[Dict[str, str]] = field(default_factory=list)
    unknowns: List[Dict[str, str]] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    integrity_problems: List[str] = field(default_factory=list)
    calculation: Dict[str, Any] = field(default_factory=dict)
    decision_rationale: List[str] = field(default_factory=list)
    statement: str = ""

    def by_family(self, family: str) -> List[ReadinessDimension]:
        return [d for d in self.dimensions if d.family == family]

    def dimension(self, key: str) -> Optional[ReadinessDimension]:
        return next((d for d in self.dimensions if d.key == key), None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "deployment_permitted": self.deployment_permitted,
            "readiness_percent": self.readiness_percent,
            "assurance_percent": self.assurance_percent,
            "evidence_status": self.evidence_status,
            "statement": self.statement,
            "decision_rationale": self.decision_rationale,
            "blockers": self.blockers,
            "conditions": self.conditions,
            "unknowns": self.unknowns,
            "strengths": self.strengths,
            "integrity_problems": self.integrity_problems,
            "calculation": self.calculation,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "independence_note": (
                "READINESS and DECISION are computed from evidence, not from the CI exit "
                "status, and neither is derived from the other. A security finding lowers "
                "readiness; it does not by itself stop the pipeline. An unmeasured dimension "
                "lowers ASSURANCE and can never raise READINESS."
            ),
        }


# ---------------------------------------------------------------------------
# Delivery dimensions -- build, tests, test coverage
# ---------------------------------------------------------------------------


def _build_dimension(policy: Any, build_status: str) -> ReadinessDimension:
    weight = policy.readiness_weight("build")
    if build_status == BUILD_PASS:
        return ReadinessDimension(
            key="build", title="Build", family=FAMILY_DELIVERY,
            state=DIM_PASS, weight=weight, score=1.0,
            statement="The caller reported the build succeeded.",
            evidence={"reported": build_status},
        )
    if build_status == BUILD_FAIL:
        return ReadinessDimension(
            key="build", title="Build", family=FAMILY_DELIVERY,
            state=DIM_FAILED, weight=weight, score=0.0, blocking=True,
            blocking_reason="The build failed. There is no artifact to deploy.",
            statement="The caller reported the build failed.",
            evidence={"reported": build_status},
        )
    return ReadinessDimension(
        key="build", title="Build", family=FAMILY_DELIVERY,
        state=DIM_NOT_REPORTED, weight=weight,
        statement=(
            "The caller did not report a build result, so build success is NOT_ESTABLISHED. "
            "It is not assumed to have succeeded."
        ),
        evidence={"reported": build_status},
    )


def _test_dimension(policy: Any, test_status_input: str) -> ReadinessDimension:
    weight = policy.readiness_weight("unit_tests")
    state = normalise_test_status(test_status_input)
    if state == DIM_PASS:
        return ReadinessDimension(
            key="unit_tests", title="Unit tests", family=FAMILY_DELIVERY,
            state=DIM_PASS, weight=weight, score=1.0,
            statement="The caller reported the unit-test suite passed.",
            evidence={"reported": test_status_input or ""},
        )
    if state == DIM_FAILED:
        return ReadinessDimension(
            key="unit_tests", title="Unit tests", family=FAMILY_DELIVERY,
            state=DIM_FAILED, weight=weight, score=0.0, blocking=True,
            blocking_reason=(
                "The unit-test suite failed. Deploying code whose own tests do not pass is a "
                "correctness risk independent of any security finding."
            ),
            statement="The caller reported the unit-test suite failed.",
            evidence={"reported": test_status_input or ""},
        )
    if state == DIM_NOT_TESTED:
        return ReadinessDimension(
            key="unit_tests", title="Unit tests", family=FAMILY_DELIVERY,
            state=DIM_NOT_TESTED, weight=weight,
            statement=(
                "The caller reported that unit tests did not run. Absence of a test result is "
                "not a passing test result."
            ),
            evidence={"reported": test_status_input or ""},
        )
    return ReadinessDimension(
        key="unit_tests", title="Unit tests", family=FAMILY_DELIVERY,
        state=DIM_NOT_REPORTED, weight=weight,
        statement=(
            "The caller did not report a unit-test result. This run establishes nothing about "
            "the test suite."
        ),
        evidence={"reported": test_status_input or ""},
    )


def _test_coverage_dimension(policy: Any, percent: Optional[float]) -> ReadinessDimension:
    weight = policy.readiness_weight("test_coverage")
    minimum = policy.readiness_min_test_coverage
    if percent is None:
        return ReadinessDimension(
            key="test_coverage", title="Test coverage", family=FAMILY_DELIVERY,
            state=DIM_NOT_REPORTED, weight=weight,
            statement=(
                "The caller did not report a test-coverage figure. Test coverage is "
                "NOT_ESTABLISHED for this run."
            ),
            evidence={"reported_percent": None, "policy_minimum_percent": minimum},
        )
    value = max(0.0, min(100.0, float(percent)))
    # The score is the measured percentage itself, not a pass/fail collapse.
    # Collapsing 31% and 79% into one "below minimum" bucket discards the only
    # information the figure carries.
    score = value / 100.0
    meets = value >= minimum
    if minimum <= 0:
        qualifier = "; this policy sets no minimum, so the figure scores as measured"
    elif meets:
        qualifier = ", meeting the policy minimum of %.1f%%" % minimum
    else:
        qualifier = ", below the policy minimum of %.1f%%" % minimum
    return ReadinessDimension(
        key="test_coverage", title="Test coverage", family=FAMILY_DELIVERY,
        state=DIM_PASS if meets else DIM_PARTIAL, weight=weight, score=score,
        statement="The caller reported %.1f%% test coverage%s." % (value, qualifier),
        evidence={"reported_percent": value, "policy_minimum_percent": minimum},
    )


# ---------------------------------------------------------------------------
# Security validation dimensions -- one per applicable category
# ---------------------------------------------------------------------------

# CategoryOutcome status -> dimension state. NOT_IMPLEMENTED becomes NOT_TESTED
# rather than NOT_VERIFIED because the two have different owners: one is a
# roadmap gap, the other is a run that should have produced a result and did not.
_CATEGORY_STATE = {
    CATEGORY_PASS: DIM_PASS,
    CATEGORY_FAILED: DIM_FAILED,
    CATEGORY_NOT_APPLICABLE: DIM_NOT_APPLICABLE,
    CATEGORY_NOT_VERIFIED: DIM_NOT_VERIFIED,
    CATEGORY_NOT_IMPLEMENTED: DIM_NOT_TESTED,
}


def _category_dimensions(policy: Any, outcomes: Sequence[Any]) -> List[ReadinessDimension]:
    """Derive one dimension per security category, from the registry itself.

    Deliberately not a hand-written list. Registering a new scanner against a
    new category makes that category part of readiness with no change here and
    no per-project branching -- which is what keeps this universal.
    """
    dimensions: List[ReadinessDimension] = []
    blocking_keys = set(policy.required_categories) | set(policy.readiness_blocking_categories)

    for outcome in outcomes:
        state = _CATEGORY_STATE.get(outcome.status, DIM_NOT_VERIFIED)
        required = outcome.key in blocking_keys
        weight = policy.readiness_weight(
            "category:%s" % outcome.key,
            default_key="required_category" if required else "default",
        )

        dimension = ReadinessDimension(
            key="category:%s" % outcome.key,
            title=outcome.title,
            family=FAMILY_SECURITY,
            state=state,
            weight=weight,
            statement=outcome.reason,
            evidence={
                "category_key": outcome.key,
                "category_status": outcome.status,
                "stage": outcome.stage,
                "phase": outcome.phase,
                "runtime": outcome.runtime,
                "tools": list(outcome.tools),
                "open_findings": outcome.finding_count,
                "required_control": required,
            },
        )
        if state == DIM_PASS:
            dimension.score = 1.0
        elif state == DIM_FAILED:
            dimension.score = 0.0
            if required:
                dimension.blocking = True
                dimension.blocking_reason = (
                    "%s is a required control and it FAILED: %s" % (outcome.title, outcome.reason)
                )
        dimensions.append(dimension)
    return dimensions


# ---------------------------------------------------------------------------
# Assurance dimensions -- did we actually look, and can the looking be trusted
# ---------------------------------------------------------------------------


def _code_coverage_dimension(policy: Any, file_coverage: Dict[str, Any]) -> ReadinessDimension:
    weight = policy.readiness_weight("code_coverage")
    if not (file_coverage or {}).get("available"):
        return ReadinessDimension(
            key="code_coverage", title="Source file coverage", family=FAMILY_ASSURANCE,
            state=DIM_NOT_VERIFIED, weight=weight,
            statement=(
                "The file-level coverage census did not complete, so how much of this "
                "codebase was read is UNKNOWN. That is not a statement that all of it was."
            ),
            evidence={"reason": (file_coverage or {}).get("reason", "")},
        )
    total = int(file_coverage.get("code_files") or 0)
    analysed = int(file_coverage.get("code_files_analysed") or 0)
    percent = float(file_coverage.get("coverage_percent") or 0.0)
    complete = bool(file_coverage.get("complete"))
    if total == 0:
        return ReadinessDimension(
            key="code_coverage", title="Source file coverage", family=FAMILY_ASSURANCE,
            state=DIM_NOT_APPLICABLE, weight=weight,
            statement="No code files were found in the workspace, so there was nothing to analyse.",
            evidence={"code_files": 0},
        )
    return ReadinessDimension(
        key="code_coverage", title="Source file coverage", family=FAMILY_ASSURANCE,
        state=DIM_PASS if complete else DIM_PARTIAL, weight=weight, score=percent / 100.0,
        statement=file_coverage.get("statement", ""),
        evidence={
            "code_files": total,
            "code_files_analysed": analysed,
            "code_files_not_analysed": int(file_coverage.get("code_files_not_analysed") or 0),
            "coverage_percent": percent,
            "buckets": dict(file_coverage.get("counts") or {}),
        },
    )


def _scanner_execution_dimension(policy: Any, scanner_results: Sequence[Any]) -> ReadinessDimension:
    weight = policy.readiness_weight("scanner_execution")
    attempted = list(scanner_results or ())
    if not attempted:
        return ReadinessDimension(
            key="scanner_execution", title="Scanner execution", family=FAMILY_ASSURANCE,
            state=DIM_NOT_VERIFIED, weight=weight,
            statement=(
                "No scanner produced an execution record in this run, so nothing is known "
                "about whether any control executed."
            ),
            evidence={"attempted": 0},
        )
    completed = [r for r in attempted if getattr(r, "is_trustworthy", False)]
    failed = [
        {
            "tool": getattr(r, "tool", ""),
            "category": getattr(r, "category_key", ""),
            "status": getattr(r, "status", ""),
            "errors": list(getattr(r, "errors", None) or ())[:3],
        }
        for r in attempted
        if not getattr(r, "is_trustworthy", False)
    ]
    score = len(completed) / float(len(attempted))
    return ReadinessDimension(
        key="scanner_execution", title="Scanner execution", family=FAMILY_ASSURANCE,
        state=DIM_PASS if not failed else DIM_PARTIAL, weight=weight, score=score,
        statement=(
            "%d of %d scanner executions completed successfully. A scanner that executed and "
            "found problems counts as completed; only a scanner that did not finish counts "
            "against this figure." % (len(completed), len(attempted))
        ),
        evidence={
            "attempted": len(attempted),
            "completed": len(completed),
            "not_completed": len(failed),
            "failures": failed,
        },
    )


def _evidence_integrity_dimension(
    policy: Any,
    outcomes: Sequence[Any],
    scanner_results: Sequence[Any],
    findings: Sequence[Finding],
    import_failures: Optional[Dict[str, str]],
) -> ReadinessDimension:
    """Can this run's own evidence be trusted to describe itself?

    Distinct from "did the scanners pass" and from "was coverage complete". This
    asks whether the evidence set is internally COHERENT. An incoherent evidence
    set is worse than a failed scan: a failed scan is a known gap, while a report
    that contradicts itself makes every other number in it unreliable.

    A contradiction is blocking and forces the decision to UNKNOWN. Nothing in
    this framework may report a verdict it cannot substantiate.
    """
    weight = policy.readiness_weight("evidence_integrity")
    contradictions: List[str] = []
    degradations: List[str] = []

    results_by_category: Dict[str, List[Any]] = {}
    for result in scanner_results or ():
        results_by_category.setdefault(getattr(result, "category_key", ""), []).append(result)

    # 1. A scanner cannot simultaneously report OK and carry a recorded
    #    degradation. If it does, one of the two is wrong and we cannot tell which.
    for result in scanner_results or ():
        if getattr(result, "status", "") == "OK" and getattr(result, "degraded", False):
            contradictions.append(
                "Scanner %s reports status OK while also recording a degradation. Its result "
                "cannot be trusted in either direction."
                % (getattr(result, "tool", "") or "<unnamed>")
            )

    # 2. A category cannot be PASS while a scanner serving it did not complete.
    #    This is the exact laundering the framework exists to prevent, asserted
    #    here as evidence rather than left to the status engine to be trusted on.
    for outcome in outcomes:
        if outcome.status != CATEGORY_PASS:
            continue
        for result in results_by_category.get(outcome.key, ()):
            if not getattr(result, "is_trustworthy", False):
                contradictions.append(
                    "Category %s is reported PASS while its scanner %s did not complete "
                    "successfully (status %s). A control cannot pass on a scan that did not run."
                    % (outcome.key, getattr(result, "tool", ""), getattr(result, "status", ""))
                )

    # 3. Findings attributed to a category that produced no scanner result at
    #    all. The findings came from somewhere; if nothing recorded producing
    #    them, their provenance is unestablished.
    finding_categories = {f.scanner_category for f in findings or () if f.scanner_category}
    for category_key in sorted(finding_categories):
        if category_key not in results_by_category:
            contradictions.append(
                "Findings are filed under category %r but no scanner recorded an execution for "
                "it. Their provenance cannot be established." % category_key
            )

    # 4. A collector module that failed to import is a real loss of evidence,
    #    but not a contradiction: the framework knows exactly what it lost.
    for name, error in sorted((import_failures or {}).items()):
        degradations.append("Collector module %r failed to import (%s)." % (name, error))

    if contradictions:
        return ReadinessDimension(
            key="evidence_integrity", title="Evidence integrity", family=FAMILY_ASSURANCE,
            state=DIM_FAILED, weight=weight, score=0.0, blocking=True,
            blocking_reason=(
                "The evidence set contradicts itself in %d place(s). No readiness figure "
                "computed from it can be relied on." % len(contradictions)
            ),
            statement=(
                "This run's evidence is internally inconsistent and cannot substantiate any "
                "verdict. See integrity_problems."
            ),
            evidence={"contradictions": contradictions, "degradations": degradations},
        )
    if degradations:
        return ReadinessDimension(
            key="evidence_integrity", title="Evidence integrity", family=FAMILY_ASSURANCE,
            state=DIM_PARTIAL, weight=weight,
            score=1.0 / (1.0 + len(degradations)),
            statement=(
                "The evidence set is self-consistent, but %d component(s) of the framework "
                "did not load, so part of the control set never had the chance to run."
                % len(degradations)
            ),
            evidence={"contradictions": [], "degradations": degradations},
        )
    return ReadinessDimension(
        key="evidence_integrity", title="Evidence integrity", family=FAMILY_ASSURANCE,
        state=DIM_PASS, weight=weight, score=1.0,
        statement=(
            "The evidence set is internally consistent: no category claims a pass on a scanner "
            "that did not complete, no scanner contradicts its own status, and every finding "
            "traces to a recorded execution."
        ),
        evidence={"contradictions": [], "degradations": []},
    )


def _finding_risk_dimension(policy: Any, findings: Sequence[Finding]) -> ReadinessDimension:
    """Severity-weighted magnitude of what was actually found.

    Separate from the category statuses on purpose. A category is FAILED whether
    it breached its threshold by one finding or by forty; readiness has to be
    able to tell those apart, because they are not the same deployment decision.

    Only OPEN, validly-suppressed-excluded, security-relevant findings count --
    the same population the status engine evaluates thresholds over, so the two
    can never disagree about what is outstanding.
    """
    weight = policy.readiness_weight("finding_risk")
    relevant = [
        f
        for f in (findings or ())
        if f.is_open and policy.is_security_finding_category(f.category) and not is_suppressed(f)
    ]
    if not policy.hotspots_count_toward_thresholds:
        relevant = [f for f in relevant if f.category != "security_hotspot"]

    counts = severity_breakdown(relevant, open_only=True)
    points_per = policy.readiness_risk_points
    contributions = {
        severity: counts.get(severity, 0) * points_per.get(severity, 0)
        for severity in SEVERITY_ORDER
    }
    risk_points = sum(contributions.values())
    zero_at = policy.readiness_risk_points_zero_score
    if zero_at > 0:
        score = max(0.0, 1.0 - (risk_points / float(zero_at)))
    else:
        score = 1.0 if risk_points == 0 else 0.0

    if risk_points == 0:
        state = DIM_PASS
    elif score <= 0.0:
        state = DIM_FAILED
    else:
        state = DIM_PARTIAL

    breakdown = ", ".join(
        "%d %s x %d" % (counts.get(s, 0), s, points_per.get(s, 0))
        for s in SEVERITY_ORDER
        if counts.get(s, 0)
    )
    dimension = ReadinessDimension(
        key="finding_risk", title="Outstanding security risk", family=FAMILY_ASSURANCE,
        state=state, weight=weight, score=score,
        statement=(
            "No open, unsuppressed security finding is outstanding."
            if risk_points == 0
            else (
                "%d open security finding(s) carry %d risk point(s) (%s). "
                "Score = max(0, 1 - %d/%d) = %.3f."
                % (
                    len(relevant), risk_points,
                    breakdown or "no weighted severities",
                    risk_points, zero_at, score,
                )
            )
        ),
        evidence={
            "open_security_findings": len(relevant),
            "severity_counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
            "points_per_severity": dict(points_per),
            "points_contributed": contributions,
            "risk_points": risk_points,
            "zero_score_at_points": zero_at,
        },
    )

    # The one severity that blocks on its own. Everything else lowers the score
    # and lands in `conditions`, so a HIGH finding stays visible and costly
    # without terminating anything.
    critical_count = counts.get(SEVERITY_CRITICAL, 0)
    critical_threshold = policy.threshold_for(SEVERITY_CRITICAL)
    if critical_threshold >= 0 and critical_count > critical_threshold:
        dimension.blocking = True
        dimension.blocking_reason = (
            "%d open CRITICAL security finding(s); policy permits %d. A CRITICAL finding is "
            "the one severity this framework will not let a deployment decision pass over "
            "silently. Accept it explicitly through the exceptions file, or remediate it."
            % (critical_count, critical_threshold)
        )
    return dimension


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _evidence_status(dimensions: Sequence[ReadinessDimension], unknown_weight: float) -> str:
    integrity = next((d for d in dimensions if d.key == "evidence_integrity"), None)
    if integrity is not None and integrity.state == DIM_FAILED:
        return EVIDENCE_UNTRUSTWORTHY
    if unknown_weight > 0:
        return EVIDENCE_INCOMPLETE
    if any(d.state == DIM_PARTIAL for d in dimensions if d.family == FAMILY_ASSURANCE):
        return EVIDENCE_INCOMPLETE
    return EVIDENCE_COMPLETE


def assess(
    policy: Any,
    assessment: Any,
    findings: Sequence[Finding],
    scanner_results: Sequence[Any],
    file_coverage: Optional[Dict[str, Any]] = None,
    test_status: str = "",
    test_coverage_percent: Optional[float] = None,
    import_failures: Optional[Dict[str, str]] = None,
) -> ReadinessAssessment:
    """Compute deployment readiness from one run's evidence.

    Never raises. A readiness assessment that cannot be computed reports
    DECISION = UNKNOWN with the reason, because an absent readiness figure must
    never read as a favourable one.
    """
    try:
        return _assess(
            policy, assessment, findings, scanner_results, file_coverage,
            test_status, test_coverage_percent, import_failures,
        )
    except Exception as exc:  # noqa: BLE001 - readiness must not take down a run
        return ReadinessAssessment(
            decision=DECISION_UNKNOWN,
            deployment_permitted=False,
            evidence_status=EVIDENCE_UNTRUSTWORTHY,
            integrity_problems=[
                "The readiness assessment did not complete: %s: %s" % (type(exc).__name__, exc)
            ],
            decision_rationale=[
                "DEPLOYMENT DECISION = UNKNOWN because readiness could not be computed. "
                "This is not a statement that the application is ready, and it is not a "
                "statement that it is not."
            ],
            statement=(
                "Deployment readiness is NOT_ESTABLISHED for this run: the assessment itself "
                "failed. Findings and scanner results elsewhere in this report are unaffected."
            ),
        )


def _assess(
    policy: Any,
    assessment: Any,
    findings: Sequence[Finding],
    scanner_results: Sequence[Any],
    file_coverage: Optional[Dict[str, Any]],
    test_status: str,
    test_coverage_percent: Optional[float],
    import_failures: Optional[Dict[str, str]],
) -> ReadinessAssessment:
    outcomes = list(getattr(assessment, "categories", None) or ())
    file_coverage = file_coverage or {}

    dimensions: List[ReadinessDimension] = [
        _build_dimension(policy, getattr(assessment, "build_status", "")),
        _test_dimension(policy, test_status),
        _test_coverage_dimension(policy, test_coverage_percent),
    ]
    dimensions.extend(_category_dimensions(policy, outcomes))
    dimensions.append(_code_coverage_dimension(policy, file_coverage))
    dimensions.append(_scanner_execution_dimension(policy, scanner_results))
    dimensions.append(
        _evidence_integrity_dimension(policy, outcomes, scanner_results, findings, import_failures)
    )
    dimensions.append(_finding_risk_dimension(policy, findings))

    measured = [d for d in dimensions if d.measured]
    unknown = [d for d in dimensions if d.unknown]
    excluded = [d for d in dimensions if d.excluded]

    measured_weight = sum(d.weight for d in measured)
    unknown_weight = sum(d.weight for d in unknown)
    excluded_weight = sum(d.weight for d in excluded)
    earned_weight = sum(d.earned for d in measured)

    readiness_percent = (
        round(100.0 * earned_weight / measured_weight, 1) if measured_weight else 0.0
    )
    total_in_scope = measured_weight + unknown_weight
    assurance_percent = (
        round(100.0 * measured_weight / total_in_scope, 1) if total_in_scope else 0.0
    )

    blockers = [
        {"dimension": d.key, "title": d.title, "reason": d.blocking_reason}
        for d in dimensions
        if d.blocking
    ]
    conditions = [
        {"dimension": d.key, "title": d.title, "state": d.state, "detail": d.statement}
        for d in dimensions
        if d.state in (DIM_FAILED, DIM_PARTIAL) and not d.blocking
    ]
    unknowns = [
        {"dimension": d.key, "title": d.title, "state": d.state, "detail": d.statement}
        for d in unknown
    ]
    strengths = ["%s: %s" % (d.title, d.statement) for d in dimensions if d.state == DIM_PASS]

    integrity = next((d for d in dimensions if d.key == "evidence_integrity"), None)
    integrity_problems: List[str] = []
    if integrity is not None:
        integrity_problems.extend(integrity.evidence.get("contradictions") or [])
        integrity_problems.extend(integrity.evidence.get("degradations") or [])

    evidence_status = _evidence_status(dimensions, unknown_weight)

    decision, rationale, permitted = _decide(
        policy=policy,
        evidence_status=evidence_status,
        measured_weight=measured_weight,
        readiness_percent=readiness_percent,
        assurance_percent=assurance_percent,
        blockers=blockers,
        conditions=conditions,
        unknowns=unknowns,
    )

    calculation = {
        "formula_readiness": (
            "100 * sum(score * weight for MEASURED dimensions) "
            "/ sum(weight for MEASURED dimensions)"
        ),
        "formula_assurance": (
            "100 * sum(weight MEASURED) / (sum(weight MEASURED) + sum(weight UNKNOWN))"
        ),
        "measured_dimensions": len(measured),
        "unknown_dimensions": len(unknown),
        "excluded_dimensions": len(excluded),
        "measured_weight": round(measured_weight, 4),
        "earned_weight": round(earned_weight, 4),
        "unknown_weight": round(unknown_weight, 4),
        "excluded_weight": round(excluded_weight, 4),
        "readiness_percent": readiness_percent,
        "assurance_percent": assurance_percent,
        "thresholds": {
            "ready_at_or_above_percent": policy.readiness_ready_threshold,
            "minimum_assurance_percent": policy.readiness_min_assurance,
            "unknown_below_assurance_percent": policy.readiness_unknown_below_assurance,
            "conditionally_ready_permits_deployment": policy.conditionally_ready_permits_deployment,
        },
        "note": (
            "Every figure above is recomputable from the dimension table: no value is "
            "assigned, estimated or carried over from a previous run. NOT_APPLICABLE "
            "dimensions are excluded from both sums; UNKNOWN dimensions are excluded from "
            "the readiness score and counted against assurance."
        ),
    }

    return ReadinessAssessment(
        dimensions=dimensions,
        readiness_percent=readiness_percent,
        assurance_percent=assurance_percent,
        decision=decision,
        deployment_permitted=permitted,
        evidence_status=evidence_status,
        blockers=blockers,
        conditions=conditions,
        unknowns=unknowns,
        strengths=strengths,
        integrity_problems=integrity_problems,
        calculation=calculation,
        decision_rationale=rationale,
        statement=_statement(decision, readiness_percent, assurance_percent, blockers, unknowns),
    )


def _decide(
    policy: Any,
    evidence_status: str,
    measured_weight: float,
    readiness_percent: float,
    assurance_percent: float,
    blockers: List[Dict[str, str]],
    conditions: List[Dict[str, str]],
    unknowns: List[Dict[str, str]],
) -> Tuple[str, List[str], bool]:
    """Resolve the deployment decision. Evaluated top to bottom; first match wins.

    The order encodes what outranks what, and it is the same fail-closed
    precedence the status engine uses: an untrustworthy evidence set outranks
    everything, because a decision drawn from it would be arbitrary.
    """
    rationale: List[str] = []

    if evidence_status == EVIDENCE_UNTRUSTWORTHY:
        rationale.append(
            "DEPLOYMENT DECISION = UNKNOWN. The evidence set for this run contradicts itself, "
            "so no readiness figure computed from it can be relied on. This is not a pass and "
            "not a failure -- it is a statement that the question cannot be answered from this "
            "run's evidence."
        )
        return DECISION_UNKNOWN, rationale, False

    if measured_weight <= 0:
        rationale.append(
            "DEPLOYMENT DECISION = UNKNOWN. Not one readiness dimension was measured in this "
            "run, so there is nothing to compute a readiness figure from. Absence of a "
            "measurement is never a pass."
        )
        return DECISION_UNKNOWN, rationale, False

    if assurance_percent < policy.readiness_unknown_below_assurance:
        rationale.append(
            "DEPLOYMENT DECISION = UNKNOWN. Only %.1f%% of the readiness weight in scope was "
            "measured at all, below the %.1f%% floor this policy requires before a readiness "
            "figure means anything. %d dimension(s) were not established."
            % (assurance_percent, policy.readiness_unknown_below_assurance, len(unknowns))
        )
        rationale.append(
            "The readiness figure of %.1f%% describes only the fraction that WAS measured. It "
            "is reported for transparency and must not be read as an overall score."
            % readiness_percent
        )
        return DECISION_UNKNOWN, rationale, False

    if blockers:
        for blocker in blockers:
            rationale.append("BLOCKER -- %s: %s" % (blocker["title"], blocker["reason"]))
        rationale.append(
            "DEPLOYMENT DECISION = NOT_READY. %d blocking condition(s) must be resolved or "
            "explicitly risk-accepted before this commit is deployable. Every other validation "
            "in this run still completed and is reported in full." % len(blockers)
        )
        return DECISION_NOT_READY, rationale, False

    if assurance_percent < policy.readiness_min_assurance:
        rationale.append(
            "%d dimension(s) were not established, so assurance is %.1f%% against a policy "
            "minimum of %.1f%%. Readiness of %.1f%% describes the measured fraction only."
            % (len(unknowns), assurance_percent, policy.readiness_min_assurance, readiness_percent)
        )
        rationale.append(
            "DEPLOYMENT DECISION = CONDITIONALLY_READY. Nothing blocks deployment, but the "
            "validation picture is incomplete: the unmeasured dimensions are listed and are "
            "not treated as passing."
        )
        return (
            DECISION_CONDITIONALLY_READY,
            rationale,
            bool(policy.conditionally_ready_permits_deployment),
        )

    if readiness_percent < policy.readiness_ready_threshold or conditions:
        for condition in conditions:
            rationale.append(
                "CONDITION -- %s is %s: %s"
                % (condition["title"], condition["state"], condition["detail"])
            )
        rationale.append(
            "DEPLOYMENT DECISION = CONDITIONALLY_READY. Readiness is %.1f%% against a %.1f%% "
            "threshold for READY, with full assurance. Nothing blocks deployment; the "
            "conditions above are outstanding and are recorded rather than waived."
            % (readiness_percent, policy.readiness_ready_threshold)
        )
        return (
            DECISION_CONDITIONALLY_READY,
            rationale,
            bool(policy.conditionally_ready_permits_deployment),
        )

    rationale.append(
        "DEPLOYMENT DECISION = READY. Every readiness dimension in scope was measured "
        "(assurance %.1f%%) and readiness is %.1f%%, at or above the %.1f%% threshold. No "
        "blocking condition and no outstanding condition remains."
        % (assurance_percent, readiness_percent, policy.readiness_ready_threshold)
    )
    rationale.append(
        "This is a statement about the controls this framework executed in this run. It is "
        "not a statement that the application contains no vulnerability: the manual control "
        "areas listed in this report remain untested by any automation."
    )
    return DECISION_READY, rationale, True


def _statement(
    decision: str,
    readiness_percent: float,
    assurance_percent: float,
    blockers: List[Dict[str, str]],
    unknowns: List[Dict[str, str]],
) -> str:
    """One sentence a non-specialist can act on."""
    if decision == DECISION_READY:
        return (
            "Deployment readiness %.1f%% with %.1f%% assurance. No blocker and no outstanding "
            "condition: this commit is READY to deploy on the evidence in this report."
            % (readiness_percent, assurance_percent)
        )
    if decision == DECISION_NOT_READY:
        return (
            "Deployment readiness %.1f%% with %.1f%% assurance. %d blocking condition(s) make "
            "this commit NOT_READY to deploy. They are listed with the exact evidence that "
            "produced them." % (readiness_percent, assurance_percent, len(blockers))
        )
    if decision == DECISION_CONDITIONALLY_READY:
        return (
            "Deployment readiness %.1f%% with %.1f%% assurance. Nothing blocks deployment, but "
            "%d dimension(s) were not established and outstanding conditions remain. Deploying "
            "is a decision somebody makes, not one this report makes for them."
            % (readiness_percent, assurance_percent, len(unknowns))
        )
    return (
        "Deployment readiness could not be established for this run (measured %.1f%%, assurance "
        "%.1f%%). UNKNOWN is not a pass: it means this evidence cannot answer the question."
        % (readiness_percent, assurance_percent)
    )
