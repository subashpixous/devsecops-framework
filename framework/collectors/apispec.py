"""42Crunch collector — OpenAPI contract security audit.

42Crunch is a hosted service. It needs both a CLI/container and an API token, so
this collector is credential-gated: without them the category reports
NOT_VERIFIED with the exact missing input. No substitute tool is used, and the
requirement is never silently dropped.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available
from .base import Collector, ScannerResult

TOOL = "42crunch"
CATEGORY_KEY = "api_spec_security"

ACCEPT_RC = (0, 1, 2)
DEFAULT_TIMEOUT = 900
TOKEN_ENV = "FORTYTWO_CRUNCH_TOKEN"
CLI = "42c-ci-scan"
IMAGE = "42crunch/scand-agent:latest"


class ApiSpecCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"workspace", "timeout", "openapi_files"}

    def __init__(
        self,
        workspace: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        openapi_files: Optional[List[str]] = None,
    ) -> None:
        self.workspace = workspace
        self.timeout = timeout
        self.openapi_files = openapi_files or []

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["specs_supplied"] = list(self.openapi_files)

        if not self.openapi_files:
            return result.skip(
                "No OpenAPI specification file was supplied or detected. API specification "
                "security was NOT audited, so this category is unverified. If the API serves its "
                "specification only at runtime, export it during the build and pass it in."
            ).finish()

        token = os.environ.get(TOKEN_ENV, "")
        has_cli = tool_available(CLI)
        has_docker = tool_available("docker")

        if not token:
            return result.skip(
                "%s is not set. 42Crunch is a hosted service and cannot audit the specification "
                "without an API token, so this category is unverified. Required input: a 42Crunch "
                "API token exposed as the %s secret." % (TOKEN_ENV, TOKEN_ENV)
            ).finish()

        if not has_cli and not has_docker:
            return result.fail(
                "Neither the %s CLI nor docker is available, so the 42Crunch audit could not run. "
                "This category is unverified." % CLI
            ).finish()

        handle, report_path = tempfile.mkstemp(prefix="42c-", suffix=".json")
        os.close(handle)
        audited: List[Dict[str, Any]] = []
        failures: List[str] = []

        try:
            for spec in self.openapi_files:
                spec_path = spec if os.path.isabs(spec) else os.path.join(self.workspace, spec)
                if not os.path.exists(spec_path):
                    failures.append("%s (not found)" % spec)
                    continue

                if has_cli:
                    argv = [CLI, "--api", spec_path, "--output", report_path, "--output-format", "json"]
                    result.metadata["runner"] = "native:%s" % CLI
                else:
                    argv = [
                        "docker", "run", "--rm",
                        "-e", "%s=%s" % (TOKEN_ENV, token),
                        "-v", "%s:/work:ro" % os.path.dirname(os.path.abspath(spec_path)),
                        IMAGE, "--api", "/work/%s" % os.path.basename(spec_path),
                    ]
                    result.metadata["runner"] = "docker:%s" % IMAGE

                proc = run(
                    argv, timeout=self.timeout, cwd=self.workspace,
                    accept_returncodes=ACCEPT_RC, extra_redactions=(token,),
                )
                if not accepted(proc, ACCEPT_RC):
                    failures.append("%s (%s)" % (spec, proc.summary()))
                    continue

                raw = ""
                if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                    with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
                        raw = fh.read()
                else:
                    raw = proc.stdout or ""

                try:
                    audited.append({"spec": spec, "report": json.loads(raw)})
                except ValueError as exc:
                    failures.append("%s (report not valid JSON: %s)" % (spec, exc))

            if not audited:
                return result.fail(
                    "42Crunch audited no specification successfully: %s" % "; ".join(failures or ["unknown error"])
                ).finish()
            if failures:
                result.partial("Some specifications could not be audited: %s" % "; ".join(failures))

            result.payload = {"_tool": TOOL, "audits": audited}
            result.metadata["specs_audited"] = len(audited)
            return result.succeed().finish()
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass


def _build_collector(**kwargs: Any) -> ApiSpecCollector:
    return ApiSpecCollector(**{k: v for k, v in kwargs.items() if k in ApiSpecCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.apispec_adapter import ApiSpecAdapter

    return ApiSpecAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="42Crunch OpenAPI specification security audit (requires FORTYTWO_CRUNCH_TOKEN).",
    )
)
