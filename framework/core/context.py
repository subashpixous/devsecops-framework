"""Run context: what is being scanned, where, and in which lifecycle state.

Nothing here is inferred. Values that cannot be established are held as empty
strings and rendered as NOT_ESTABLISHED in every report, never guessed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .schema import utc_now

NOT_ESTABLISHED = "NOT_ESTABLISHED"


def established(value: Optional[str]) -> str:
    """Render a value for reporting, marking blanks explicitly."""
    text = (value or "").strip()
    return text if text else NOT_ESTABLISHED


@dataclass
class RunContext:
    """Immutable-ish description of one framework execution."""

    project_name: str = ""
    repository: str = ""
    commit: str = ""
    branch: str = ""
    environment: str = ""
    deployment_target: str = ""
    deployed_url: str = ""
    workspace: str = "."
    active_phase: int = 1
    framework_version: str = "0.0.0"
    run_id: str = ""
    run_url: str = ""
    started_at: str = field(default_factory=utc_now)

    # Lifecycle inputs supplied by the caller; never inferred from each other.
    build_status_input: str = ""
    deployment_status_input: str = ""

    @classmethod
    def from_environment(cls, overrides: Optional[Dict[str, Any]] = None) -> "RunContext":
        """Build context from GitHub Actions environment plus explicit overrides.

        Overrides always win. Absent values stay empty -- they are not filled in
        from unrelated signals.
        """
        overrides = {k: v for k, v in (overrides or {}).items() if v not in (None, "")}

        repo_full = os.environ.get("GITHUB_REPOSITORY", "")
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        run_id = os.environ.get("GITHUB_RUN_ID", "")

        branch = os.environ.get("GITHUB_REF_NAME", "")
        # For pull_request events GITHUB_REF_NAME is "<n>/merge"; the head ref is
        # the meaningful branch name.
        head_ref = os.environ.get("GITHUB_HEAD_REF", "")
        if head_ref:
            branch = head_ref

        context = cls(
            project_name=repo_full.split("/")[-1] if repo_full else "",
            repository=("%s/%s" % (server, repo_full)) if repo_full else "",
            commit=os.environ.get("GITHUB_SHA", ""),
            branch=branch,
            workspace=os.environ.get("GITHUB_WORKSPACE", "."),
            run_id=run_id,
            run_url=("%s/%s/actions/runs/%s" % (server, repo_full, run_id)) if repo_full and run_id else "",
        )

        for key, value in overrides.items():
            if hasattr(context, key):
                setattr(context, key, value)
        return context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": established(self.project_name),
            "repository": established(self.repository),
            "commit": established(self.commit),
            "commit_short": (self.commit[:8] if self.commit else NOT_ESTABLISHED),
            "branch": established(self.branch),
            "environment": established(self.environment),
            "deployment_target": established(self.deployment_target),
            "deployed_url": established(self.deployed_url),
            "active_phase": self.active_phase,
            "framework_version": self.framework_version,
            "run_id": established(self.run_id),
            "run_url": established(self.run_url),
            "started_at": self.started_at,
        }
