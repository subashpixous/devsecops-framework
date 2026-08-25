"""Run evidence manifest -- what would let someone else reproduce this verdict.

A security report says what was found. An evidence manifest says what produced
it: which framework version, which policy, which scanner binaries at which
versions, which commit, which analysis, and a content hash of every artefact
written. Without it a report is an assertion; with it, a report is a record.

The manifest deliberately answers the questions an auditor asks and a findings
list cannot:

  * Which exact code was validated?              commit, branch, repository
  * By which exact tooling?                      framework + scanner versions
  * Under which rules?                           policy identity and thresholds
  * Did every control actually execute?          per-scanner execution record
  * What was produced, and has it changed?       SHA-256 of every artefact
  * What was NOT established?                    limitations, carried verbatim

WHAT THIS IS NOT
----------------
This is not a signature and does not pretend to be. The hashes prove internal
consistency -- that the report you are reading is the report that was written --
not authenticity. Anyone who can rewrite the artefacts can rewrite the manifest.
Signing is a separate concern and is deliberately left to the release pipeline
rather than half-implemented here, because a manifest that *looks* cryptographic
without being so is worse than one that states its own limits.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from typing import Any, Dict, List, Optional, Sequence

from .schema import utc_now

MANIFEST_FILENAME = "evidence-manifest.json"
MANIFEST_VERSION = 1

# Read in chunks so a large SBOM or SARIF file cannot spike memory.
_HASH_CHUNK = 1024 * 1024


def sha256_file(path: str) -> str:
    """SHA-256 of a file, or an explicit marker when it cannot be read."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                digest.update(chunk)
    except OSError as exc:
        return "UNREADABLE: %s" % exc
    return digest.hexdigest()


def _scanner_record(result: Any) -> Dict[str, Any]:
    """One scanner's execution record, as evidence rather than as a summary."""
    metadata = getattr(result, "metadata", None) or {}
    tool_run = metadata.get("tool_run") or {}
    return {
        "tool": getattr(result, "tool", ""),
        "category": getattr(result, "category_key", ""),
        "status": getattr(result, "status", ""),
        "trustworthy": bool(getattr(result, "is_trustworthy", False)),
        "degraded": bool(getattr(result, "degraded", False)),
        "started_at": getattr(result, "started_at", ""),
        "finished_at": getattr(result, "finished_at", ""),
        "version": metadata.get("version", "NOT_ESTABLISHED"),
        # The exit status is the difference between "found nothing" and "did not
        # run", which is the distinction this whole framework exists to preserve.
        "exit_code": tool_run.get("returncode", "NOT_ESTABLISHED"),
        "command": tool_run.get("argv", tool_run.get("command", "NOT_ESTABLISHED")),
        "duration_seconds": tool_run.get("duration", "NOT_ESTABLISHED"),
        "timed_out": tool_run.get("timed_out", False),
        "error_count": len(getattr(result, "errors", None) or ()),
        "warning_count": len(getattr(result, "warnings", None) or ()),
        "errors": list(getattr(result, "errors", None) or ()),
        "raw_evidence_file": os.path.basename(getattr(result, "raw_path", "") or "") or "NONE",
    }


def build_manifest(
    report: Dict[str, Any],
    scanner_results: Sequence[Any],
    output_dir: str,
    artefacts: Optional[Sequence[str]] = None,
    policy_paths: Optional[Sequence[str]] = None,
    workflow_ref: str = "",
) -> Dict[str, Any]:
    """Assemble the evidence manifest for one run.

    Never raises. An evidence manifest that fails to build must not take down
    the run that produced the evidence.
    """
    try:
        return _build(report, scanner_results, output_dir, artefacts, policy_paths, workflow_ref)
    except Exception as exc:  # noqa: BLE001 - evidence must not break a run
        return {
            "manifest_version": MANIFEST_VERSION,
            "available": False,
            "reason": "the evidence manifest could not be assembled: %s: %s"
                      % (type(exc).__name__, exc),
            "warning": (
                "This run produced reports but no reproducibility record. The reports are still "
                "valid; their provenance is NOT_ESTABLISHED."
            ),
        }


def _build(
    report: Dict[str, Any],
    scanner_results: Sequence[Any],
    output_dir: str,
    artefacts: Optional[Sequence[str]],
    policy_paths: Optional[Sequence[str]],
    workflow_ref: str,
) -> Dict[str, Any]:
    project = report.get("project") or {}
    framework = report.get("framework") or {}
    policy = report.get("policy") or {}
    status = report.get("status") or {}
    gate = report.get("quality_gate") or {}
    coverage = report.get("file_coverage") or {}

    # Hash every artefact actually on disk, so the manifest describes the files
    # a reader has rather than the files we intended to write.
    if artefacts is None:
        try:
            artefacts = sorted(
                name for name in os.listdir(output_dir)
                if os.path.isfile(os.path.join(output_dir, name)) and name != MANIFEST_FILENAME
            )
        except OSError:
            artefacts = []

    artefact_records: List[Dict[str, Any]] = []
    for name in artefacts:
        path = name if os.path.isabs(name) else os.path.join(output_dir, name)
        if not os.path.isfile(path):
            continue
        artefact_records.append({
            "file": os.path.basename(path),
            "bytes": os.path.getsize(path),
            "sha256": sha256_file(path),
        })

    scanners = [_scanner_record(r) for r in scanner_results]
    executed = [s for s in scanners if s["trustworthy"]]

    return {
        "manifest_version": MANIFEST_VERSION,
        "available": True,
        "generated_at": utc_now(),

        # --- WHAT was validated -------------------------------------------
        "subject": {
            "repository": project.get("repository", "NOT_ESTABLISHED"),
            "commit": project.get("commit", "NOT_ESTABLISHED"),
            "branch": project.get("branch", "NOT_ESTABLISHED"),
            "project_name": project.get("project_name", "NOT_ESTABLISHED"),
            "environment": project.get("environment", "NOT_ESTABLISHED"),
            "deployed_url": project.get("deployed_url", "NOT_ESTABLISHED"),
        },

        # --- BY WHAT it was validated -------------------------------------
        "tooling": {
            "framework_name": framework.get("name", ""),
            "framework_version": framework.get("version", "NOT_ESTABLISHED"),
            "workflow_ref": workflow_ref or os.environ.get("GITHUB_WORKFLOW_SHA", "NOT_ESTABLISHED"),
            "active_phase": framework.get("active_phase", "NOT_ESTABLISHED"),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "runner": os.environ.get("RUNNER_NAME", "NOT_ESTABLISHED"),
            "ci_run_id": os.environ.get("GITHUB_RUN_ID", "NOT_ESTABLISHED"),
            "ci_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "NOT_ESTABLISHED"),
        },

        # --- UNDER WHAT RULES ----------------------------------------------
        "policy": {
            "name": policy.get("name", "NOT_ESTABLISHED"),
            "schema_version": policy.get("schema_version", "NOT_ESTABLISHED"),
            "active_phase": policy.get("active_phase", "NOT_ESTABLISHED"),
            "required_categories": policy.get("required_categories", []),
            "severity_thresholds": policy.get("severity_thresholds", {}),
            "sources": list(policy_paths or policy.get("source_paths") or []),
        },

        # --- DID THE CONTROLS ACTUALLY RUN --------------------------------
        "execution": {
            "scanners_registered": len(scanners),
            "scanners_completed": len(executed),
            "scanners_not_completed": len(scanners) - len(executed),
            "scanner_records": scanners,
        },

        # --- THE ANALYSIS THIS RUN DEPENDED ON ----------------------------
        # SonarQube results are produced elsewhere, so their identity is part of
        # this run's provenance rather than part of its execution.
        "external_analysis": {
            "sonarqube": {
                "state": gate.get("analysis_state", "NOT_ESTABLISHED"),
                "project_key": gate.get("project_key", "NOT_ESTABLISHED"),
                "analysis_date": gate.get("analysis_date", "NOT_ESTABLISHED"),
                "analysis_revision": gate.get("analysis_revision", "NOT_ESTABLISHED"),
                "commit_under_validation": gate.get("scanned_commit", "NOT_ESTABLISHED"),
                "freshness_basis": gate.get("freshness_basis", "NOT_ESTABLISHED"),
                "quality_gate": gate.get("status", "UNKNOWN"),
            }
        },

        # --- WHAT WAS COVERED ---------------------------------------------
        "coverage": {
            "available": coverage.get("available", False),
            "code_files": coverage.get("code_files", "NOT_ESTABLISHED"),
            "code_files_analysed": coverage.get("code_files_analysed", "NOT_ESTABLISHED"),
            "code_files_not_analysed": coverage.get("code_files_not_analysed", "NOT_ESTABLISHED"),
            "coverage_percent": coverage.get("coverage_percent", "NOT_ESTABLISHED"),
            "complete": coverage.get("complete", False),
            "scanners_unavailable": coverage.get("scanners_unavailable", []),
            "scanners_failed": coverage.get("scanners_failed", []),
            "statement": coverage.get("statement", ""),
        },

        # --- THE VERDICT ---------------------------------------------------
        "verdict": {
            "build": status.get("build", "UNKNOWN"),
            "deployment": status.get("deployment", "UNKNOWN"),
            "security": status.get("security", "NOT_VERIFIED"),
            "runtime_security": status.get("runtime_security", "NOT_TESTED"),
            "verdict_scope": status.get("verdict_scope", ""),
            "coverage_complete": status.get("coverage_complete", False),
            "open_findings": (report.get("findings") or {}).get("open", 0),
        },

        # --- WHAT WAS NOT ESTABLISHED --------------------------------------
        # Carried verbatim. An evidence record that omits its own limits is not
        # evidence; it is marketing.
        "limitations": report.get("limitations", []),
        "manual_controls_not_tested": [
            control.get("title", control.get("key", ""))
            for control in (report.get("manual_controls") or [])
        ],

        # --- INTEGRITY ------------------------------------------------------
        "artefacts": artefact_records,
        "integrity_note": (
            "SHA-256 digests establish that these artefacts have not changed since the run that "
            "produced them. They are NOT signatures and do not establish authenticity: anyone "
            "able to modify the artefacts can recompute the digests. Authenticity requires "
            "signing the manifest in the release pipeline."
        ),
    }


def write_manifest(manifest: Dict[str, Any], output_dir: str) -> str:
    import json

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, MANIFEST_FILENAME)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return path
