"""OWASP ZAP collector — dynamic application security testing.

Runs the ZAP *baseline* scan by default: passive analysis plus safe spidering.
The active scan is opt-in (`zap_mode: full`) because active scanning sends
attack payloads and must never be launched against production by default.

Execution path, in order of preference:
  1. `zap-baseline.py` / `zap-full-scan.py` on PATH
  2. the official container image via `docker run`
Neither available -> the category is unverified, never passed.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "owasp-zap"
CATEGORY_KEY = "dast_zap"

# ZAP exits 1 when warnings are present and 2 for failures-with-results.
# All three mean the scan completed and produced a report.
ACCEPT_RC = (0, 1, 2)
DEFAULT_TIMEOUT = 2400
IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

MODE_SCRIPT = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py"}


class ZapCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"target_url", "timeout", "zap_mode"}

    def __init__(self, target_url: str = "", timeout: int = DEFAULT_TIMEOUT, zap_mode: str = "baseline") -> None:
        self.target_url = (target_url or "").strip()
        self.timeout = timeout
        self.zap_mode = (zap_mode or "baseline").strip().lower()

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["mode"] = self.zap_mode

        if not self.target_url:
            return result.skip(
                "No deployed URL was supplied (input 'deployed_url'). Dynamic application security "
                "testing did NOT run, so this category is unverified."
            ).finish()

        if self.zap_mode not in MODE_SCRIPT:
            return result.fail("Unknown ZAP mode %r; expected 'baseline' or 'full'." % self.zap_mode).finish()

        script = MODE_SCRIPT[self.zap_mode]
        if self.zap_mode == "full":
            result.metadata["active_scan"] = True
            result.warnings.append(
                "ZAP full (active) scan requested. Active scanning sends attack payloads and must "
                "only be run against an environment where that is authorised."
            )

        workdir = tempfile.mkdtemp(prefix="zap-")
        report_name = "zap-report.json"
        report_path = os.path.join(workdir, report_name)

        if tool_available(script):
            argv = [script, "-t", self.target_url, "-J", report_path, "-I"]
            result.metadata["runner"] = "native:%s" % script
            result.metadata["version"] = tool_version(script, ("-h",))
            proc = run(argv, timeout=self.timeout, cwd=workdir, accept_returncodes=ACCEPT_RC)
        elif tool_available("docker"):
            argv = [
                "docker", "run", "--rm",
                "-v", "%s:/zap/wrk:rw" % workdir,
                IMAGE, script,
                "-t", self.target_url,
                "-J", report_name,
                "-I",
            ]
            result.metadata["runner"] = "docker:%s" % IMAGE
            proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
        else:
            return result.fail(
                "Neither the ZAP scripts (%s) nor docker are available. DAST did NOT run, so this "
                "category is unverified." % script
            ).finish()

        result.metadata["tool_run"] = proc.to_dict()

        if not accepted(proc, ACCEPT_RC) and not os.path.exists(report_path):
            return result.fail("ZAP did not complete: %s" % proc.summary()).finish()

        if not os.path.exists(report_path):
            return result.fail("ZAP produced no JSON report; results cannot be trusted.").finish()

        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
                payload = json.load(fh)
        except (OSError, ValueError) as exc:
            return result.fail("ZAP report could not be read or parsed: %s" % exc).finish()

        if not isinstance(payload, dict) or "site" not in payload:
            return result.fail("ZAP report has no 'site' section; output cannot be trusted.").finish()

        payload["_mode"] = self.zap_mode
        payload["_target"] = self.target_url
        result.payload = payload
        result.metadata["sites"] = len(payload.get("site") or [])
        if self.zap_mode == "baseline":
            result.warnings.append(
                "Baseline (passive) scan only. Active vulnerability classes such as injection are "
                "NOT covered by this mode."
            )
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> ZapCollector:
    mapped = dict(kwargs)
    if "deployed_url" in mapped and "target_url" not in mapped:
        mapped["target_url"] = mapped["deployed_url"]
    return ZapCollector(**{k: v for k, v in mapped.items() if k in ZapCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.zap_adapter import ZapAdapter

    return ZapAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="OWASP ZAP baseline/full dynamic application security testing.",
    )
)
