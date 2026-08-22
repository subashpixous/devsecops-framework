"""Security Status Engine.

Produces four INDEPENDENT statuses:

    BUILD             PASS | FAIL | UNKNOWN
    DEPLOYMENT        DEPLOYED | FAILED | SKIPPED
    SECURITY          PASS | FAILED | NOT_VERIFIED
    RUNTIME_SECURITY  PASS | FAILED | NOT_TESTED

Invariants enforced here and covered by unit tests:

  * A scanner failure, absence, partial result, skip or malformed payload can
    only produce NOT_VERIFIED. It can never produce PASS.
  * Deployment status is never an input to the security computation. A
    successful deployment cannot raise a security status, and a failed
    deployment cannot lower one.
  * Every category resolves to exactly one of PASS / FAILED / NOT_VERIFIED /
    NOT_APPLICABLE / NOT_IMPLEMENTED. Nothing is silently dropped.
  * SECURITY = PASS is only reachable when every required category is PASS, and
    it is always emitted with the scope that qualifies it.
  * Only validly suppressed findings (unexpired false-positive / accepted-risk)
    are excluded from thresholds. An expired suppression counts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .categories import (
    BUILD_FAIL,
    BUILD_PASS,
    BUILD_UNKNOWN,
    CATEGORY_FAILED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_PASS,
    CATEGORY_REGISTRY,
    DEPLOYMENT_DEPLOYED,
    DEPLOYMENT_FAILED,
    DEPLOYMENT_SKIPPED,
    RUNTIME_FAILED,
    RUNTIME_NOT_TESTED,
    RUNTIME_PASS,
    SECURITY_FAILED,
    SECURITY_NOT_VERIFIED,
    SECURITY_PASS,
    CategoryOutcome,
    evaluate_applicability,
)
from .context import RunContext
from .lifecycle import LifecycleSummary, is_suppressed
from .manual_controls import manual_control_state
from .policy import UNLIMITED, Policy
from .schema import Finding, SEVERITY_ORDER, severity_breakdown

_EXTENSION_LANGUAGE = {
    ".cs": "csharp", ".vb": "vbnet", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".py": "python", ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".dart": "dart", ".swift": "swift", ".scala": "scala",
    ".html": "html", ".htm": "html", ".css": "css", ".vue": "vue",
    ".svelte": "svelte", ".sql": "sql", ".sh": "shell", ".ps1": "powershell",
}

_NON_CODE_LANGUAGES = {"html", "css", "sql", "shell", "powershell"}

# Categories evaluated by the framework itself rather than by an external scanner.
FRAMEWORK_INTERNAL_CATEGORIES = {"finding_lifecycle"}


def normalise_build_status(value: str) -> str:
    token = (value or "").strip().lower()
    if token in ("pass", "passed", "success", "succeeded", "true", "ok"):
        return BUILD_PASS
    if token in ("fail", "failed", "failure", "false", "error"):
        return BUILD_FAIL
    return BUILD_UNKNOWN


def normalise_deployment_status(value: str) -> str:
    token = (value or "").strip().lower()
    if token in ("deployed", "success", "succeeded", "pass", "passed", "true"):
        return DEPLOYMENT_DEPLOYED
    if token in ("failed", "failure", "fail", "error", "false"):
        return DEPLOYMENT_FAILED
    return DEPLOYMENT_SKIPPED


@dataclass
class ThresholdBreach:
    severity: str
    count: int
    threshold: int

    def to_dict(self) -> Dict[str, Any]:
        return {"severity": self.severity, "count": self.count, "threshold": self.threshold}


@dataclass
class SecurityAssessment:
    build_status: str = BUILD_UNKNOWN
    deployment_status: str = DEPLOYMENT_SKIPPED
    security_status: str = SECURITY_NOT_VERIFIED
    runtime_security_status: str = RUNTIME_NOT_TESTED

    verdict_scope: str = ""
    coverage_complete: bool = False
    categories: List[CategoryOutcome] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)
    threshold_breaches: List[ThresholdBreach] = field(default_factory=list)
    quality_gate: Dict[str, Any] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    security_severity_counts: Dict[str, int] = field(default_factory=dict)
    limitations: List[Dict[str, str]] = field(default_factory=list)
    manual_controls: List[Dict[str, str]] = field(default_factory=list)
    lifecycle: Dict[str, Any] = field(default_factory=dict)
    stages_executed: List[str] = field(default_factory=list)

    def categories_by_status(self, status: str) -> List[CategoryOutcome]:
        return [c for c in self.categories if c.status == status]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build_status": self.build_status,
            "deployment_status": self.deployment_status,
            "security_status": self.security_status,
            "runtime_security_status": self.runtime_security_status,
            "verdict_scope": self.verdict_scope,
            "coverage_complete": self.coverage_complete,
            "stages_executed": self.stages_executed,
            "rationale": self.rationale,
            "threshold_breaches": [b.to_dict() for b in self.threshold_breaches],
            "quality_gate": self.quality_gate,
            "severity_counts": self.severity_counts,
            "security_severity_counts": self.security_severity_counts,
            "categories": [c.to_dict() for c in self.categories],
            "limitations": self.limitations,
            "manual_controls": self.manual_controls,
            "lifecycle": self.lifecycle,
        }


class StatusEngine:
    """Turns scanner results and findings into the four statuses."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    # -- Category resolution --------------------------------------------------

    def _resolve_categories(
        self,
        capabilities: Dict[str, Any],
        scanner_results: List[Any],
        findings: List[Finding],
        quality_gate: Dict[str, Any],
        lifecycle: Optional[LifecycleSummary],
        stages: Optional[Sequence[str]],
    ) -> Tuple[List[CategoryOutcome], List[ThresholdBreach]]:
        results_by_category: Dict[str, List[Any]] = {}
        for result in scanner_results:
            results_by_category.setdefault(result.category_key, []).append(result)

        findings_by_category: Dict[str, List[Finding]] = {}
        for finding in findings:
            findings_by_category.setdefault(finding.scanner_category, []).append(finding)

        outcomes: List[CategoryOutcome] = []
        all_breaches: List[ThresholdBreach] = []

        for category in CATEGORY_REGISTRY:
            applicable, reason, blocking_note = evaluate_applicability(category, capabilities)
            outcome = CategoryOutcome(
                key=category.key,
                title=category.title,
                phase=category.phase,
                status=CATEGORY_NOT_VERIFIED,
                tools=list(category.tools),
                runtime=category.runtime,
                stage=category.stage,
            )
            if blocking_note:
                outcome.notes.append(blocking_note)

            if not applicable:
                outcome.status = CATEGORY_NOT_APPLICABLE
                outcome.reason = "Not applicable to this project (%s)." % reason
                outcomes.append(outcome)
                continue

            if category.phase > self.policy.active_phase:
                outcome.status = CATEGORY_NOT_IMPLEMENTED
                outcome.reason = (
                    "Applicable to this project but scheduled for Phase %d; the active phase is %d. "
                    "This control has NOT been tested." % (category.phase, self.policy.active_phase)
                )
                outcomes.append(outcome)
                continue

            # Stage filtering: a category outside the executed stages was not run.
            if stages and category.stage not in stages:
                outcome.status = CATEGORY_NOT_VERIFIED
                outcome.reason = (
                    "Stage %s was not executed in this run, so this control did not run and is "
                    "unverified." % category.stage
                )
                outcomes.append(outcome)
                continue

            # Framework-internal categories are evaluated directly.
            if category.key in FRAMEWORK_INTERNAL_CATEGORIES:
                outcomes.append(self._resolve_lifecycle_category(outcome, lifecycle))
                continue

            category_results = results_by_category.get(category.key, [])
            category_findings = findings_by_category.get(category.key, [])
            outcome.finding_count = len([f for f in category_findings if f.is_open and not is_suppressed(f)])

            if not category_results:
                outcome.status = CATEGORY_NOT_VERIFIED
                outcome.reason = (
                    "No scanner produced a result for this category in this run. "
                    "Absence of results is not evidence of absence of findings."
                )
                outcomes.append(outcome)
                continue

            untrustworthy = [r for r in category_results if not r.is_trustworthy]
            if untrustworthy:
                messages = []
                for result in untrustworthy:
                    for error in result.errors:
                        messages.append("%s: %s" % (result.tool, error))
                    for warning in result.warnings:
                        messages.append("%s: %s" % (result.tool, warning))
                    if not result.errors and not result.warnings:
                        messages.append("%s returned status %s" % (result.tool, result.status))
                outcome.status = CATEGORY_NOT_VERIFIED
                outcome.reason = "Scanner did not complete successfully, so this category could not be verified."
                outcome.notes.extend(messages)
                outcomes.append(outcome)
                continue

            for result in category_results:
                outcome.notes.extend("%s: %s" % (result.tool, w) for w in result.warnings)

            breaches = self._evaluate_thresholds(category_findings)
            gate_failed = (
                self.policy.fail_on_quality_gate_error
                and quality_gate.get("status") == "ERROR"
                and category.key in self.policy.required_categories
            )

            if breaches or gate_failed:
                outcome.status = CATEGORY_FAILED
                parts = []
                if breaches:
                    parts.append(
                        "open security findings exceed policy thresholds (%s)"
                        % ", ".join("%s: %d > %d" % (b.severity, b.count, b.threshold) for b in breaches)
                    )
                if gate_failed:
                    failing = quality_gate.get("failing_conditions") or []
                    parts.append(
                        "upstream quality gate status is ERROR%s"
                        % (" (" + ", ".join(c.get("metric", "?") for c in failing) + ")" if failing else "")
                    )
                outcome.reason = "Security condition failed: " + "; ".join(parts) + "."
                all_breaches.extend(breaches)
            else:
                outcome.status = CATEGORY_PASS
                outcome.reason = (
                    "Scanner completed successfully and no open security finding breaches the "
                    "configured thresholds."
                )

            outcomes.append(outcome)

        return outcomes, all_breaches

    def _resolve_lifecycle_category(
        self, outcome: CategoryOutcome, lifecycle: Optional[LifecycleSummary]
    ) -> CategoryOutcome:
        """Finding lifecycle is evaluated by the framework, not by a scanner."""
        if lifecycle is None:
            outcome.status = CATEGORY_NOT_VERIFIED
            outcome.reason = "Finding aggregation did not run, so lifecycle state is unknown."
            return outcome

        outcome.notes.extend(lifecycle.notes)
        outcome.finding_count = lifecycle.new + lifecycle.existing

        if lifecycle.expired_exceptions:
            outcome.status = CATEGORY_FAILED
            outcome.reason = (
                "%d suppression(s) have expired or carry no expiry date. Their findings are NOT "
                "suppressed and count against policy. Expired exceptions are a governance failure."
                % lifecycle.expired_exceptions
            )
            return outcome

        if not lifecycle.baseline_available:
            outcome.status = CATEGORY_NOT_VERIFIED
            outcome.reason = (
                "No baseline was available, so NEW/EXISTING/FIXED state could not be determined. "
                "Findings are reported as NEW by default."
            )
            return outcome

        outcome.status = CATEGORY_PASS
        outcome.reason = (
            "Lifecycle computed against baseline %s: %d new, %d existing, %d fixed, %d suppressed."
            % (
                lifecycle.baseline_source,
                lifecycle.new,
                lifecycle.existing,
                lifecycle.fixed,
                lifecycle.false_positive + lifecycle.accepted_risk,
            )
        )
        return outcome

    def _evaluate_thresholds(self, findings: List[Finding]) -> List[ThresholdBreach]:
        relevant = [
            f
            for f in findings
            if f.is_open
            and self.policy.is_security_finding_category(f.category)
            and not is_suppressed(f)  # only VALID suppressions are excluded
        ]
        if not self.policy.hotspots_count_toward_thresholds:
            relevant = [f for f in relevant if f.category != "security_hotspot"]

        counts = severity_breakdown(relevant, open_only=True)
        breaches: List[ThresholdBreach] = []
        for severity in SEVERITY_ORDER:
            threshold = self.policy.threshold_for(severity)
            if threshold == UNLIMITED:
                continue
            count = counts.get(severity, 0)
            if count > threshold:
                breaches.append(ThresholdBreach(severity=severity, count=count, threshold=threshold))
        return breaches

    # -- Top-level statuses ---------------------------------------------------

    def _security_status(self, outcomes: List[CategoryOutcome]) -> Tuple[str, List[str]]:
        rationale: List[str] = []
        static = [c for c in outcomes if not c.runtime]
        by_key = {c.key: c for c in static}

        required = self.policy.required_categories
        missing_required = [key for key in required if key not in by_key]
        for key in missing_required:
            rationale.append(
                "Required category %r is not declared in the category registry; treated as unverified." % key
            )

        failed = [c for c in static if c.status == CATEGORY_FAILED]
        required_not_pass = [
            by_key[key] for key in required if key in by_key and by_key[key].status != CATEGORY_PASS
        ]

        if failed:
            for outcome in failed:
                rationale.append("%s FAILED: %s" % (outcome.title, outcome.reason))
            for outcome in [c for c in required_not_pass if c.status != CATEGORY_FAILED]:
                rationale.append(
                    "%s is %s and also could not be verified: %s"
                    % (outcome.title, outcome.status, outcome.reason)
                )
            rationale.append(
                "SECURITY = FAILED. A confirmed failure takes precedence over unverified controls; "
                "unverified controls remain listed above and are not treated as passing."
            )
            return SECURITY_FAILED, rationale

        if missing_required or required_not_pass:
            for outcome in required_not_pass:
                rationale.append("Required control %s is %s: %s" % (outcome.title, outcome.status, outcome.reason))
            rationale.append(
                "SECURITY = NOT_VERIFIED. A required control did not complete successfully, so no "
                "assertion about security can be made. This is NOT a pass."
            )
            return SECURITY_NOT_VERIFIED, rationale

        rationale.append(
            "SECURITY = PASS for the controls implemented and executed in this run only. Every "
            "required control executed successfully and no open finding breaches policy."
        )
        return SECURITY_PASS, rationale

    def _runtime_status(self, outcomes: List[CategoryOutcome]) -> Tuple[str, List[str]]:
        rationale: List[str] = []
        runtime = [c for c in outcomes if c.runtime]
        applicable = [c for c in runtime if c.status != CATEGORY_NOT_APPLICABLE]

        failed = [c for c in applicable if c.status == CATEGORY_FAILED]
        if failed:
            for outcome in failed:
                rationale.append("%s FAILED: %s" % (outcome.title, outcome.reason))
            return RUNTIME_FAILED, rationale

        tested = [c for c in applicable if c.status == CATEGORY_PASS]
        untested = [c for c in applicable if c.status in (CATEGORY_NOT_IMPLEMENTED, CATEGORY_NOT_VERIFIED)]

        if untested or not tested:
            for outcome in untested:
                rationale.append("%s is %s: %s" % (outcome.title, outcome.status, outcome.reason))
            rationale.append(
                "RUNTIME_SECURITY = NOT_TESTED. Runtime security was not fully verified against a "
                "running instance in this run."
            )
            return RUNTIME_NOT_TESTED, rationale

        rationale.append("RUNTIME_SECURITY = PASS for the runtime controls executed in this run.")
        return RUNTIME_PASS, rationale

    # -- Limitations ----------------------------------------------------------

    def _limitations(
        self,
        capabilities: Dict[str, Any],
        outcomes: List[CategoryOutcome],
        findings: List[Finding],
        scanner_results: List[Any],
        import_failures: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, str]]:
        limitations: List[Dict[str, str]] = []

        not_implemented = [c for c in outcomes if c.status == CATEGORY_NOT_IMPLEMENTED]
        if not_implemented:
            limitations.append(
                {
                    "code": "PHASE_SCOPE_INCOMPLETE",
                    "detail": (
                        "%d applicable security categories are not yet implemented and were NOT tested: %s."
                        % (len(not_implemented), ", ".join(sorted(c.title for c in not_implemented)))
                    ),
                }
            )

        not_verified = [c for c in outcomes if c.status == CATEGORY_NOT_VERIFIED]
        if not_verified:
            limitations.append(
                {
                    "code": "CATEGORIES_NOT_VERIFIED",
                    "detail": (
                        "%d applicable categories could not be verified in this run: %s."
                        % (len(not_verified), ", ".join(sorted(c.title for c in not_verified)))
                    ),
                }
            )

        detected = {
            str(language)
            for language in (capabilities.get("languages") or [])
            if str(language) not in _NON_CODE_LANGUAGES
        }
        observed = set()
        for finding in findings:
            extension = os.path.splitext(finding.file or "")[1].lower()
            language = _EXTENSION_LANGUAGE.get(extension)
            if language:
                observed.add(language)
        unconfirmed = sorted(detected - observed)
        if unconfirmed:
            limitations.append(
                {
                    "code": "SAST_LANGUAGE_COVERAGE_UNCONFIRMED",
                    "detail": (
                        "No static-analysis findings were returned for these detected languages: %s. "
                        "This may mean the code is clean, or that the analyser did not scan the "
                        "language at all. Confirm lines-of-code per language on the analysis server."
                        % ", ".join(unconfirmed)
                    ),
                }
            )

        for name, error in (import_failures or {}).items():
            limitations.append(
                {
                    "code": "SCANNER_MODULE_IMPORT_FAILED",
                    "detail": "Collector module %r failed to load (%s); its category is unverified." % (name, error),
                }
            )

        for result in scanner_results:
            for warning in result.warnings:
                limitations.append({"code": "SCANNER_WARNING", "detail": "%s: %s" % (result.tool, warning)})
            for error in result.errors:
                limitations.append({"code": "SCANNER_ERROR", "detail": "%s: %s" % (result.tool, error)})

        limitations.append(
            {
                "code": "MANUAL_CONTROLS_NOT_AUTOMATED",
                "detail": (
                    "Automated scanning cannot detect authorization and business-logic classes of "
                    "vulnerability. 11 manual control areas remain untested and are listed in full "
                    "in the manual controls section. Required follow-up: manual security review, "
                    "threat modeling, authenticated testing, penetration testing, runtime "
                    "monitoring and cloud security review."
                ),
            }
        )
        return limitations

    # -- Entry point ----------------------------------------------------------

    def evaluate(
        self,
        context: RunContext,
        capabilities: Dict[str, Any],
        scanner_results: List[Any],
        findings: List[Finding],
        quality_gate: Optional[Dict[str, Any]] = None,
        lifecycle: Optional[LifecycleSummary] = None,
        stages: Optional[Sequence[str]] = None,
        import_failures: Optional[Dict[str, str]] = None,
    ) -> SecurityAssessment:
        quality_gate = quality_gate or {"status": "UNKNOWN", "conditions": [], "failing_conditions": []}

        outcomes, breaches = self._resolve_categories(
            capabilities, scanner_results, findings, quality_gate, lifecycle, stages
        )
        security_status, security_rationale = self._security_status(outcomes)
        runtime_status, runtime_rationale = self._runtime_status(outcomes)

        build_status = normalise_build_status(context.build_status_input)
        deployment_status = normalise_deployment_status(context.deployment_status_input)

        rationale = list(security_rationale) + list(runtime_rationale)
        if build_status == BUILD_UNKNOWN:
            rationale.append("BUILD status was not reported by the caller; recorded as UNKNOWN rather than assumed.")
        if not context.deployment_status_input:
            rationale.append(
                "DEPLOYMENT status was not reported by the caller; recorded as SKIPPED. Deployment "
                "state has no influence on the security verdict."
            )

        executed = sorted(
            c.key for c in outcomes if c.status in (CATEGORY_PASS, CATEGORY_FAILED)
        )
        coverage_complete = not any(
            c.status in (CATEGORY_NOT_IMPLEMENTED, CATEGORY_NOT_VERIFIED) for c in outcomes
        )

        security_relevant = [
            f for f in findings
            if self.policy.is_security_finding_category(f.category) and not is_suppressed(f)
        ]

        return SecurityAssessment(
            build_status=build_status,
            deployment_status=deployment_status,
            security_status=security_status,
            runtime_security_status=runtime_status,
            verdict_scope="PHASE_%d[%s]" % (self.policy.active_phase, ",".join(executed) or "none"),
            coverage_complete=coverage_complete,
            categories=outcomes,
            rationale=rationale,
            threshold_breaches=breaches,
            quality_gate=quality_gate,
            severity_counts=severity_breakdown(findings, open_only=True),
            security_severity_counts=severity_breakdown(security_relevant, open_only=True),
            limitations=self._limitations(capabilities, outcomes, findings, scanner_results, import_failures),
            manual_controls=manual_control_state(),
            lifecycle=lifecycle.to_dict() if lifecycle else {},
            stages_executed=list(stages) if stages else [],
        )
