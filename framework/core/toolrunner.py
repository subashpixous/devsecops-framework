"""External tool execution.

Every CLI-based scanner runs through here so that availability checking,
timeouts, output capture, secret redaction and failure semantics are identical
across tools.

Contract:
  * `run()` never raises. A missing binary, a timeout, a crash and a non-zero
    exit are all returned as data.
  * Captured output is redacted before it can reach a log or a report.
  * A tool that is not installed is a FAILURE to verify, never a pass.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

DEFAULT_TIMEOUT = 900  # 15 minutes; scanners on large repos are slow

# Environment variables whose values must never appear in captured output.
SECRET_ENV_NAMES = (
    "SONAR_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID", "FORTYTWO_CRUNCH_TOKEN",
    "SEMGREP_APP_TOKEN", "DOCKER_HUB_TOKEN", "COSIGN_PASSWORD",
    "COSIGN_PRIVATE_KEY", "ZAP_API_KEY", "NUCLEI_API_KEY",
)

# Generic high-confidence secret shapes, redacted regardless of origin.
_REDACT_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"-----BEGIN[^-]{0,40}PRIVATE KEY-----"),
    re.compile(r"(?i)(pwd|password|passwd)\s*=\s*[^;\s\"']{6,}"),
)

REDACTED = "<REDACTED>"


def redact(text: str, extra: Sequence[str] = ()) -> str:
    """Remove secret material from text before it is logged or stored."""
    if not text:
        return ""
    out = text

    # Values of known secret-bearing environment variables.
    for name in SECRET_ENV_NAMES:
        value = os.environ.get(name)
        if value and len(value) >= 6:
            out = out.replace(value, REDACTED)
    for value in extra:
        if value and len(str(value)) >= 6:
            out = out.replace(str(value), REDACTED)

    for pattern in _REDACT_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


@dataclass
class ToolResult:
    """Outcome of one external command."""

    tool: str
    argv: List[str] = field(default_factory=list)
    available: bool = False
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.available and not self.timed_out and not self.error and self.returncode == 0

    def summary(self) -> str:
        if not self.available:
            return "%s is not installed or not on PATH" % self.tool
        if self.timed_out:
            return "%s timed out after %.0fs" % (self.tool, self.duration_seconds)
        if self.error:
            return "%s failed to execute: %s" % (self.tool, self.error)
        return "%s exited with code %s" % (self.tool, self.returncode)

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool,
            # argv is recorded for reproducibility; it is redacted like any output.
            "argv": [redact(a) for a in self.argv],
            "available": self.available,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 2),
            "timed_out": self.timed_out,
            "error": self.error,
            "stderr_tail": redact(self.stderr)[-2000:],
        }


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def tool_version(binary: str, args: Sequence[str] = ("--version",)) -> str:
    """Best-effort version string; empty when unavailable."""
    if not tool_available(binary):
        return ""
    try:
        proc = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=30,
            errors="replace",
        )
        return redact((proc.stdout or proc.stderr or "").strip().splitlines()[0] if (proc.stdout or proc.stderr) else "")
    except Exception:  # noqa: BLE001 - version probing must never break a run
        return ""


def run(
    argv: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    accept_returncodes: Sequence[int] = (0,),
    extra_redactions: Sequence[str] = (),
) -> ToolResult:
    """Execute a command. Never raises.

    `accept_returncodes` exists because several scanners deliberately exit
    non-zero when they find something (gitleaks, trivy, checkov, semgrep).
    A "findings present" exit code is a successful scan, not a failed one.
    """
    argv = [str(a) for a in argv]
    result = ToolResult(tool=argv[0] if argv else "<empty>", argv=list(argv))

    if not argv:
        result.error = "empty command"
        return result

    if not tool_available(argv[0]):
        result.available = False
        result.error = "binary not found on PATH"
        return result

    result.available = True
    merged_env = dict(os.environ)
    if env:
        merged_env.update({k: str(v) for k, v in env.items()})

    started = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            errors="replace",
        )
        result.returncode = proc.returncode
        result.stdout = proc.stdout or ""
        result.stderr = redact(proc.stderr or "", extra_redactions)
    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.error = "timed out after %ds" % timeout
    except OSError as exc:
        result.error = "OS error: %s" % exc
    except Exception as exc:  # noqa: BLE001 - boundary guard
        result.error = "unexpected error: %s" % exc
    finally:
        result.duration_seconds = time.time() - started

    # Normalise "found findings" exit codes into success.
    if result.returncode is not None and result.returncode in accept_returncodes:
        result.error = result.error or ""
    return result


def accepted(result: ToolResult, accept_returncodes: Sequence[int]) -> bool:
    """True when the tool ran to completion with an acceptable exit code."""
    return (
        result.available
        and not result.timed_out
        and not result.error
        and result.returncode in accept_returncodes
    )
