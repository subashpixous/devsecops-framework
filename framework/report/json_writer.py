"""final-report.json -- the machine-readable source of truth.

Every other report format renders from this document, so the Markdown, the PDF
and any future dashboard can never disagree with each other.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..core.categories import (
    CATEGORY_FAILED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_PASS,
)
from ..core.context import RunContext
from ..core.policy import Policy
from ..core.schema import Finding, sort_findings, utc_now
from ..core.status_engine import SecurityAssessment

SCHEMA_VERSION = 2


def _lifecycle_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        state = getattr(finding, "lifecycle", "UNKNOWN") or "UNKNOWN"
        counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


def build_report(
    context: RunContext,
    capabilities: Dict[str, Any],
    policy: Policy,
    assessment: SecurityAssessment,
    findings: List[Finding],
    scanner_results: List[Any],
    file_coverage: Optional[Dict[str, Any]] = None,
    enrichment: Optional[Dict[str, Any]] = None,
    correlation: Optional[Dict[str, Any]] = None,
    readiness: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the complete report document."""
    ordered = sort_findings(findings)
    open_findings = [f for f in ordered if f.is_open]

    def keys_with_status(status: str) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in assessment.categories if c.status == status]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "framework": {
            "name": "Universal Production DevSecOps Security Validation Framework",
            "version": context.framework_version,
            "active_phase": policy.active_phase,
        },
        "project": context.to_dict(),
        "capabilities": capabilities,
        "policy": policy.to_dict(),
        # The four statuses are deliberately siblings: none is derived from another.
        "status": {
            "build": assessment.build_status,
            "deployment": assessment.deployment_status,
            "security": assessment.security_status,
            "runtime_security": assessment.runtime_security_status,
            "verdict_scope": assessment.verdict_scope,
            "coverage_complete": assessment.coverage_complete,
            "stages_executed": assessment.stages_executed,
            "independence_note": (
                "BUILD, DEPLOYMENT, SECURITY and RUNTIME_SECURITY are independent. A successful "
                "deployment does not imply a security pass, and a security failure does not imply a "
                "deployment failure."
            ),
        },
        # PIPELINE EXECUTION STATUS. Filled in by the CLI once every artefact
        # has been attempted, because only then is it known. The placeholder is
        # deliberately not COMPLETED: a document that never reached the end of
        # the run must not claim the run reached the end.
        "pipeline": {
            "status": "INCOMPLETE",
            "artifacts_written": [],
            "errors": [],
            "statement": (
                "This report was serialised before the run finished writing its artefacts. "
                "If this value survives into the published document, the run did not complete."
            ),
        },
        # DEPLOYMENT READINESS. Independent of `status` above: readiness is
        # computed from what the run established, `status` is the security
        # verdict, and neither is derived from the other.
        "readiness": readiness or {
            "decision": "UNKNOWN",
            "deployment_permitted": False,
            "readiness_percent": 0.0,
            "assurance_percent": 0.0,
            "evidence_status": "UNTRUSTWORTHY",
            "statement": (
                "Deployment readiness was not assessed for this report. UNKNOWN is not a "
                "pass: it means this document cannot answer whether the commit is deployable."
            ),
            "decision_rationale": [],
            "blockers": [], "conditions": [], "unknowns": [], "strengths": [],
            "integrity_problems": [], "calculation": {}, "dimensions": [],
        },
        "verdict": {
            "security_status": assessment.security_status,
            "rationale": assessment.rationale,
            "threshold_breaches": [b.to_dict() for b in assessment.threshold_breaches],
        },
        "quality_gate": assessment.quality_gate,
        # FINDING AGGREGATION: new / existing / fixed / suppressed / expired
        "lifecycle": assessment.lifecycle,
        "findings": {
            "total": len(ordered),
            "open": len(open_findings),
            "by_lifecycle": _lifecycle_counts(ordered),
            "severity_breakdown": assessment.severity_counts,
            "security_severity_breakdown": assessment.security_severity_counts,
            "items": [f.to_dict() for f in ordered],
        },
        "scanners": [r.to_dict() for r in scanner_results],
        # File-level coverage: which files a scanner actually read. The category
        # model answers "which control ran"; this answers "was any of my code
        # never looked at", which no category status can express.
        "file_coverage": file_coverage or {
            "available": False,
            "reason": "the file-coverage census was not run for this report",
            "warning": (
                "File-level coverage is UNKNOWN for this run. This is not a statement that "
                "every file was analysed."
            ),
        },
        # Exploitability context. Reported as its own block with explicit
        # availability states, because "no finding is KEV-listed" and "we could
        # not reach the KEV feed" are opposite conclusions that must never
        # render identically.
        "enrichment": enrichment or {
            "epss_status": "EPSS_DISABLED",
            "kev_status": "KEV_DISABLED",
            "statement": (
                "Exploitability enrichment did not run for this report. No finding carries an "
                "EPSS score or known-exploited status; this is absence of data, not evidence "
                "that the findings are not exploited."
            ),
        },
        # Corroboration across scanners. Retained as evidence, never merged.
        "correlation": correlation or {
            "groups": [], "corroborated_defects": 0, "findings_correlated": 0,
            "statement": "Cross-scanner correlation did not run for this report.",
        },
        "categories": [c.to_dict() for c in assessment.categories],
        "category_summary": {
            "passed": keys_with_status(CATEGORY_PASS),
            "failed": keys_with_status(CATEGORY_FAILED),
            "not_verified": keys_with_status(CATEGORY_NOT_VERIFIED),
            "not_implemented": keys_with_status(CATEGORY_NOT_IMPLEMENTED),
            "not_applicable": keys_with_status(CATEGORY_NOT_APPLICABLE),
        },
        "manual_controls": assessment.manual_controls,
        "limitations": assessment.limitations,
    }


def write_json(report: Dict[str, Any], output_dir: str, filename: str = "final-report.json") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return path


def write_normalized_findings(
    findings: List[Finding], output_dir: str, filename: str = "normalized-findings.json"
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "count": len(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return path
