"""SonarQube result collector -- STRICTLY READ-ONLY.

Contract:
  * Only HTTP GET is ever issued. There is no code path in this module that can
    POST, PUT, PATCH or DELETE.
  * Only public reporting endpoints are used. No administration endpoint is
    touched, no SonarQube data is modified, and no server configuration is read.
  * Credentials come from the environment (SONAR_TOKEN / SONAR_HOST_URL) and are
    never logged, echoed, written to disk, or placed in a URL.
  * Every failure returns a ScannerResult marked FAILED/PARTIAL. The collector
    never raises past its own boundary and never reports success it did not have.

Endpoints used:
  GET /api/server/version
  GET /api/qualitygates/project_status
  GET /api/issues/search
  GET /api/hotspots/search
  GET /api/rules/show            (metadata enrichment only)
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ..core.categories import SCANNER_OK
from ..core.registry import ScannerRegistration, register_scanner
from .base import Collector, ScannerResult

TOOL = "sonarqube"
CATEGORY_KEY = "sast_sonarqube"

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
PAGE_SIZE = 500
# SonarQube refuses paging past 10000 results.
MAX_PAGEABLE = 10000
MAX_RULE_LOOKUPS = 150

ISSUE_TYPES = "VULNERABILITY,BUG,CODE_SMELL"
ISSUE_STATUSES = "OPEN,CONFIRMED,REOPENED"

_PROPERTY_FILES = ("sonar-project.properties", ".sonarcloud.properties", ".sonarqube.properties")


def redact_host(url: str) -> str:
    """Return a loggable form of the host with any embedded credential removed."""
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = "%s:%s" % (netloc, parts.port)
        return urllib.parse.urlunsplit((parts.scheme, netloc, "", "", ""))
    except ValueError:
        return "<unparsable-host>"


def resolve_project_key(workspace: str, explicit: Optional[str] = None) -> Tuple[str, str]:
    """Find the SonarQube project key without hard-coding anything.

    Resolution order: explicit input -> SONAR_PROJECT_KEY -> sonar properties
    files -> Maven -> MSBuild -> Gradle. Returns (key, source) with an empty key
    when it cannot be established.
    """
    if explicit:
        return explicit.strip(), "explicit input"

    env_key = os.environ.get("SONAR_PROJECT_KEY", "").strip()
    if env_key:
        return env_key, "SONAR_PROJECT_KEY environment variable"

    candidates: List[str] = []
    for name in _PROPERTY_FILES:
        candidates.append(os.path.join(workspace, name))
        # Monorepos frequently keep the properties file one level down.
        try:
            for entry in sorted(os.listdir(workspace)):
                sub = os.path.join(workspace, entry)
                if os.path.isdir(sub) and not entry.startswith("."):
                    candidates.append(os.path.join(sub, name))
        except OSError:
            pass

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    stripped = line.strip()
                    if stripped.startswith("#") or "=" not in stripped:
                        continue
                    key, _, value = stripped.partition("=")
                    if key.strip() == "sonar.projectKey" and value.strip():
                        return value.strip(), os.path.relpath(path, workspace)
        except OSError:
            continue

    # Maven / MSBuild / Gradle fallbacks
    patterns = (
        ("pom.xml", re.compile(r"<sonar\.projectKey>\s*([^<\s]+)\s*</sonar\.projectKey>")),
        ("gradle.properties", re.compile(r"systemProp\.sonar\.projectKey\s*=\s*(\S+)")),
    )
    for filename, pattern in patterns:
        path = os.path.join(workspace, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    match = pattern.search(handle.read())
                if match:
                    return match.group(1), filename
            except OSError:
                continue

    csproj_pattern = re.compile(r"<SonarQubeProjectKey>\s*([^<\s]+)\s*</SonarQubeProjectKey>")
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "bin", "obj", "dist"}]
        if root.count(os.sep) - workspace.count(os.sep) > 3:
            dirs[:] = []
            continue
        for filename in files:
            if filename.endswith(".csproj"):
                try:
                    with open(os.path.join(root, filename), "r", encoding="utf-8", errors="replace") as handle:
                        match = csproj_pattern.search(handle.read())
                    if match:
                        return match.group(1), os.path.relpath(os.path.join(root, filename), workspace)
                except OSError:
                    continue

    return "", "NOT_ESTABLISHED"


class SonarQubeCollector(Collector):
    """Read-only SonarQube Web API collector."""

    tool = TOOL
    category_key = CATEGORY_KEY

    def __init__(
        self,
        host_url: Optional[str] = None,
        token: Optional[str] = None,
        project_key: Optional[str] = None,
        branch: str = "",
        workspace: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        enrich_rules: bool = True,
    ) -> None:
        self.host_url = (host_url if host_url is not None else os.environ.get("SONAR_HOST_URL", "")).strip().rstrip("/")
        self._token = token if token is not None else os.environ.get("SONAR_TOKEN", "")
        self.workspace = workspace
        self.project_key_input = project_key
        self.branch = (branch or "").strip()
        self.timeout = timeout
        self.retries = max(1, retries)
        self.enrich_rules = enrich_rules
        self.branch_supported = True

    # -- HTTP -----------------------------------------------------------------

    def _auth_header(self) -> str:
        # SonarQube user tokens authenticate as the username with an empty password.
        raw = ("%s:" % self._token).encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str], int]:
        """Issue one GET. Returns (payload, error_message, http_status).

        This is the only network primitive in the module and it is GET-only.
        """
        query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v not in (None, "")})
        url = "%s%s%s" % (self.host_url, path, ("?" + query if query else ""))

        last_error = "unknown transport error"
        last_status = 0
        for attempt in range(1, self.retries + 1):
            request = urllib.request.Request(url, method="GET")
            request.add_header("Authorization", self._auth_header())
            request.add_header("Accept", "application/json")
            request.add_header("User-Agent", "devsecops-framework/readonly-collector")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    last_status = response.status
                    body = response.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body), None, last_status
                except ValueError as exc:
                    return None, "malformed JSON from %s: %s" % (path, exc), last_status
            except urllib.error.HTTPError as exc:
                last_status = exc.code
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:300]
                except Exception:  # pragma: no cover - best effort only
                    detail = ""
                last_error = "HTTP %s from %s%s" % (exc.code, path, (": " + detail) if detail else "")
                # Client errors are deterministic; retrying cannot help.
                if 400 <= exc.code < 500:
                    return None, last_error, last_status
            except urllib.error.URLError as exc:
                last_error = "network failure contacting %s: %s" % (redact_host(self.host_url), exc.reason)
            except (TimeoutError, OSError) as exc:
                last_error = "transport failure contacting %s: %s" % (redact_host(self.host_url), exc)

            if attempt < self.retries:
                time.sleep(min(2 ** attempt, 8))

        return None, last_error, last_status

    def _get_with_branch_fallback(
        self, path: str, params: Dict[str, Any], result: ScannerResult
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """GET with the branch parameter, retrying without it if unsupported.

        SonarQube Community Build has no branch analysis, so a branch parameter is
        rejected. Falling back is correct, but the fallback is recorded so the
        report states which scope the data actually covers.
        """
        if self.branch and self.branch_supported:
            payload, error, status = self._get(path, dict(params, branch=self.branch))
            if payload is not None:
                return payload, None
            if status in (400, 404):
                self.branch_supported = False
                result.warnings.append(
                    "Branch parameter rejected by the server (HTTP %s); results cover the project default "
                    "branch, not %r. This is expected on SonarQube Community Build." % (status, self.branch)
                )
            else:
                return None, error

        payload, error, _ = self._get(path, params)
        return payload, error

    # -- Paging ---------------------------------------------------------------

    def _paginate(
        self, path: str, params: Dict[str, Any], list_key: str, result: ScannerResult
    ) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
        """Collect every page. Returns (items, error, truncated)."""
        items: List[Dict[str, Any]] = []
        page = 1
        truncated = False

        while True:
            page_params = dict(params, p=page, ps=PAGE_SIZE)
            payload, error = self._get_with_branch_fallback(path, page_params, result)
            if payload is None:
                return items, error, truncated

            batch = payload.get(list_key)
            if batch is None:
                return items, "response from %s has no %r array" % (path, list_key), truncated
            items.extend(batch)

            paging = payload.get("paging") or {}
            total = int(paging.get("total") or payload.get("total") or len(items))
            page_size = int(paging.get("pageSize") or PAGE_SIZE)

            if total > MAX_PAGEABLE:
                truncated = True
                total = MAX_PAGEABLE

            if len(items) >= total or not batch or page * page_size >= total:
                break
            page += 1
            if page * page_size > MAX_PAGEABLE:
                truncated = True
                break

        return items, None, truncated

    # -- Enrichment -----------------------------------------------------------

    def _fetch_rule_metadata(self, rule_keys: List[str], result: ScannerResult) -> Dict[str, Dict[str, Any]]:
        """Fetch CWE/OWASP standards for rules. Best-effort metadata only."""
        metadata: Dict[str, Dict[str, Any]] = {}
        if not self.enrich_rules:
            return metadata

        if len(rule_keys) > MAX_RULE_LOOKUPS:
            result.warnings.append(
                "Rule metadata enrichment limited to the first %d of %d distinct rules; "
                "CWE/OWASP mapping may be incomplete for the remainder."
                % (MAX_RULE_LOOKUPS, len(rule_keys))
            )
            rule_keys = rule_keys[:MAX_RULE_LOOKUPS]

        failures = 0
        for rule_key in rule_keys:
            payload, error, _ = self._get("/api/rules/show", {"key": rule_key})
            if payload is None or "rule" not in payload:
                failures += 1
                continue
            rule = payload["rule"]
            metadata[rule_key] = {
                "securityStandards": rule.get("securityStandards") or [],
                "name": rule.get("name") or "",
                "type": rule.get("type") or "",
                "remediation": rule.get("remFnBaseEffort") or "",
                "htmlDesc": "",  # deliberately not stored: large and not needed downstream
            }
        if failures:
            result.warnings.append(
                "CWE/OWASP enrichment unavailable for %d rule(s); those findings carry rule keys "
                "and tags but no standards mapping." % failures
            )
        return metadata

    # -- Main entry point -----------------------------------------------------

    def collect(self) -> ScannerResult:  # noqa: C901 - linear orchestration, kept explicit
        result = self.new_result()
        result.metadata["read_only"] = True
        result.metadata["host"] = redact_host(self.host_url)

        if not self.host_url:
            return result.fail(
                "SONAR_HOST_URL is not set. SonarQube results could not be collected."
            ).finish()
        if not self._token:
            return result.fail(
                "SONAR_TOKEN is not set. SonarQube results could not be collected."
            ).finish()

        project_key, key_source = resolve_project_key(self.workspace, self.project_key_input)
        result.metadata["project_key"] = project_key or "NOT_ESTABLISHED"
        result.metadata["project_key_source"] = key_source
        if not project_key:
            return result.fail(
                "SonarQube project key could not be established from the repository "
                "(checked sonar properties files, Maven, MSBuild and Gradle)."
            ).finish()

        payload: Dict[str, Any] = {
            "collector": "sonarqube",
            "read_only": True,
            "project_key": project_key,
            "branch_requested": self.branch,
        }

        # 1. Server version (context for the report; failure is non-fatal).
        version_payload, version_error, _ = self._get("/api/server/version")
        if version_payload is None:
            # /api/server/version returns text/plain on some versions.
            raw_version, raw_error, _ = self._get_text("/api/server/version")
            if raw_version:
                payload["server_version"] = raw_version
                result.metadata["server_version"] = raw_version
            else:
                result.warnings.append("Server version unavailable: %s" % (version_error or raw_error))
                payload["server_version"] = "NOT_ESTABLISHED"
        else:
            payload["server_version"] = version_payload

        # 2. Quality gate -- an authoritative, explicit security signal.
        gate, gate_error = self._get_with_branch_fallback(
            "/api/qualitygates/project_status", {"projectKey": project_key}, result
        )
        if gate is None:
            result.fail("Quality gate status could not be retrieved: %s" % gate_error)
            payload["quality_gate"] = None
        else:
            payload["quality_gate"] = gate

        # 3. Issues.
        issues, issues_error, issues_truncated = self._paginate(
            "/api/issues/search",
            {
                "componentKeys": project_key,
                "types": ISSUE_TYPES,
                "statuses": ISSUE_STATUSES,
                "additionalFields": "rules",
            },
            "issues",
            result,
        )
        if issues_error is not None:
            result.fail("Issue search failed: %s" % issues_error)
        payload["issues"] = issues
        if issues_truncated:
            result.partial(
                "Issue set truncated at the SonarQube %d-result paging limit; the finding list is incomplete."
                % MAX_PAGEABLE
            )

        # 4. Security hotspots (separate endpoint on modern SonarQube).
        hotspots, hotspots_error, hotspots_truncated = self._paginate(
            "/api/hotspots/search", {"projectKey": project_key}, "hotspots", result
        )
        if hotspots_error is not None:
            result.partial(
                "Security hotspots could not be retrieved (%s); the hotspot category is not covered by this run."
                % hotspots_error
            )
        payload["hotspots"] = hotspots
        if hotspots_truncated:
            result.partial("Hotspot set truncated at the SonarQube paging limit; the hotspot list is incomplete.")

        # 5. Rule metadata for CWE/OWASP mapping.
        security_rules = sorted(
            {
                issue.get("rule", "")
                for issue in issues
                if issue.get("type") == "VULNERABILITY" and issue.get("rule")
            }
        )
        payload["rules"] = self._fetch_rule_metadata(security_rules, result)

        payload["branch_scope"] = self.branch if (self.branch and self.branch_supported) else "project default branch"
        result.metadata["branch_scope"] = payload["branch_scope"]
        result.metadata["issue_count"] = len(issues)
        result.metadata["hotspot_count"] = len(hotspots)
        result.payload = payload

        result.succeed()
        return result.finish()

    def _get_text(self, path: str) -> Tuple[Optional[str], Optional[str], int]:
        """GET returning plain text (only used for /api/server/version)."""
        url = "%s%s" % (self.host_url, path)
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", self._auth_header())
        request.add_header("User-Agent", "devsecops-framework/readonly-collector")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8", errors="replace").strip(), None, response.status
        except Exception as exc:  # noqa: BLE001 - non-fatal metadata lookup
            return None, str(exc), 0


_COLLECTOR_KWARGS = {
    "host_url", "token", "project_key", "branch", "workspace", "timeout", "retries", "enrich_rules",
}


def _build_collector(**kwargs: Any) -> SonarQubeCollector:
    """Factories receive a common kwarg bag; each takes only what it understands."""
    return SonarQubeCollector(**{k: v for k, v in kwargs.items() if k in _COLLECTOR_KWARGS})


def _build_adapter(**kwargs: Any) -> Any:
    from ..adapters.sonarqube_adapter import SonarQubeAdapter

    return SonarQubeAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Read-only SonarQube Web API collector (quality gate, issues, hotspots).",
    )
)

__all__ = ["SonarQubeCollector", "resolve_project_key", "redact_host", "TOOL", "CATEGORY_KEY", "SCANNER_OK"]
