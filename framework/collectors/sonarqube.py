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
  GET /api/project_analyses/search   (analysis identity: date + revision)
  GET /api/measures/component        (coverage, duplication, size, counts)
  GET /api/rules/show                (metadata enrichment only)

ANALYSIS IDENTITY
-----------------
SonarQube is the one scanner this framework does not execute: it reads results
someone else's analysis produced. That makes "which code do these results
describe?" a question no other collector has to ask, and answering it wrong is
the only remaining way this framework can report a PASS that does not describe
the commit under test.

So the collector establishes the identity of the analysis it read -- its date and
its revision -- and compares that revision against the commit being validated.
A mismatch, or an analysis older than the permitted age, is STALE: reported,
never silently accepted, and never PASS.
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
from datetime import datetime, timedelta, timezone
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

# --- Analysis state ----------------------------------------------------------
# Four outcomes, reported verbatim in every report. Only the first one permits
# the category to be asserted PASS.
SONARQUBE_SCAN_COMPLETED = "SONARQUBE_SCAN_COMPLETED"
SONARQUBE_RESULT_STALE = "SONARQUBE_RESULT_STALE"
SONARQUBE_RESULT_UNAVAILABLE = "SONARQUBE_RESULT_UNAVAILABLE"
SONARQUBE_PERMISSION_ERROR = "SONARQUBE_PERMISSION_ERROR"

# Which SonarQube permission each read endpoint requires. When one of these
# returns 401/403 the report can name the exact grant that is missing rather
# than emitting a generic "permission error" an administrator cannot act on.
#
# Every endpoint this collector uses needs project-level "Browse". That matters
# for diagnosis: a PROJECT ANALYSIS TOKEN carries only "Execute Analysis", which
# is enough to submit a scan and NOT enough to read its results -- producing
# exactly the symptom of an analysis job that succeeds while the collector is
# refused.
ENDPOINT_PERMISSIONS = {
    "/api/server/version": "none (public endpoint)",
    "/api/qualitygates/project_status": "Browse on the project",
    "/api/issues/search": "Browse on the project",
    "/api/hotspots/search": "Browse on the project",
    "/api/project_analyses/search": "Browse on the project",
    "/api/measures/component": "Browse on the project",
    "/api/components/tree": "Browse on the project",
    "/api/rules/show": "authenticated user",
}

ANALYSIS_STATES = (
    SONARQUBE_SCAN_COMPLETED,
    SONARQUBE_RESULT_STALE,
    SONARQUBE_RESULT_UNAVAILABLE,
    SONARQUBE_PERMISSION_ERROR,
)

# How old an analysis may be before it stops describing "now". Only consulted
# when the revision cannot be compared -- a revision match is authoritative at
# any age, and a revision mismatch is stale at any age.
DEFAULT_MAX_ANALYSIS_AGE_DAYS = 7

# Measures worth reporting. Absent metrics are reported as NOT_ESTABLISHED
# rather than zero: a project with no coverage measurement is not a project
# with 0% coverage, and the two must never render identically.
MEASURE_METRICS = (
    "coverage", "line_coverage", "branch_coverage",
    "duplicated_lines_density", "ncloc", "files",
    "vulnerabilities", "bugs", "code_smells", "security_hotspots",
    "reliability_rating", "security_rating", "sqale_rating",
)

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


def parse_sonar_datetime(value: str) -> Optional[datetime]:
    """Parse a SonarQube timestamp (``2026-08-24T09:12:33+0000``).

    SonarQube emits an RFC-822 style offset with no colon, which
    ``datetime.fromisoformat`` rejects before Python 3.11. Normalised here so the
    freshness check behaves identically on every supported interpreter.
    Returns None for anything unparsable -- an unreadable date is treated as
    "not established", never as "recent".
    """
    text = (value or "").strip()
    if not text:
        return None
    normalised = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    for candidate in (normalised, normalised.replace("Z", "+00:00")):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def evaluate_freshness(
    analysis_date: Optional[datetime],
    analysis_revision: str,
    scanned_commit: str,
    max_age_days: int = DEFAULT_MAX_ANALYSIS_AGE_DAYS,
    now: Optional[datetime] = None,
) -> Tuple[bool, str, str]:
    """Decide whether an analysis describes the code being validated.

    Returns (fresh, basis, explanation). `basis` names WHICH check decided it,
    because "fresh by revision" and "fresh by age" are very different assurances
    and the report must not present them as the same claim.

    Revision comparison is authoritative when both revisions are known: an
    analysis of the exact commit under test is current at any age, and an
    analysis of a different commit is stale no matter how recent.
    """
    now = now or datetime.now(timezone.utc)

    if analysis_revision and scanned_commit:
        # Servers and CI abbreviate SHAs inconsistently; compare on the shorter.
        width = min(len(analysis_revision), len(scanned_commit))
        if width >= 7 and analysis_revision[:width].lower() == scanned_commit[:width].lower():
            return True, "revision", (
                "The analysis read from the server was produced from revision %s, which is the "
                "commit under validation." % analysis_revision[:12]
            )
        return False, "revision", (
            "The analysis read from the server was produced from revision %s, but the commit "
            "under validation is %s. These results describe different code."
            % (analysis_revision[:12] or "NOT_ESTABLISHED", scanned_commit[:12])
        )

    if analysis_date is None:
        return False, "unknown", (
            "The server did not report when this project was last analysed, so it cannot be "
            "shown that these results describe the current code."
        )

    age = now - analysis_date
    if age > timedelta(days=max_age_days):
        return False, "age", (
            "The most recent analysis on the server is %d day(s) old (%s) and no revision was "
            "reported, so it cannot be shown to describe the current code. The permitted age is "
            "%d day(s)." % (age.days, analysis_date.strftime("%Y-%m-%dT%H:%M:%SZ"), max_age_days)
        )
    if age < timedelta(0):
        return False, "age", (
            "The most recent analysis is dated in the future (%s); the server clock or the "
            "reported date cannot be trusted."
            % analysis_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    return True, "age", (
        "The most recent analysis is %d day(s) old (%s), within the permitted %d day(s). No "
        "revision was reported, so this is an age-based assurance only -- it does not prove the "
        "analysis covered the exact commit under validation."
        % (age.days, analysis_date.strftime("%Y-%m-%dT%H:%M:%SZ"), max_age_days)
    )


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
        commit: str = "",
        max_analysis_age_days: int = DEFAULT_MAX_ANALYSIS_AGE_DAYS,
    ) -> None:
        self.host_url = (host_url if host_url is not None else os.environ.get("SONAR_HOST_URL", "")).strip().rstrip("/")
        self._token = token if token is not None else os.environ.get("SONAR_TOKEN", "")
        self.workspace = workspace
        self.project_key_input = project_key
        self.branch = (branch or "").strip()
        self.timeout = timeout
        self.retries = max(1, retries)
        self.enrich_rules = enrich_rules
        # The commit under validation. Empty means the freshness check falls back
        # to analysis age, which is a weaker assurance and says so in the report.
        self.commit = (commit or "").strip()
        self.max_analysis_age_days = max(1, int(max_analysis_age_days or DEFAULT_MAX_ANALYSIS_AGE_DAYS))
        self.branch_supported = True
        # Set the moment any endpoint returns 401/403, so an authorisation
        # problem is reported as exactly that rather than as a generic failure.
        self.permission_denied = False
        # Endpoint -> status, for every endpoint that refused us. A single bool
        # cannot tell an administrator which permission to grant.
        self.permission_denied_endpoints: Dict[str, int] = {}

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
                # An authorisation failure is a distinct, actionable condition:
                # the token is wrong, expired, or lacks "Browse" on this project.
                # Recorded so the report names the cause instead of reporting a
                # generic scan failure the reader cannot act on.
                if exc.code in (401, 403):
                    self.permission_denied = True
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
            self._note_status(status, path)
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

        payload, error, status = self._get(path, params)
        self._note_status(status, path)
        return payload, error

    def _note_status(self, status: int, path: str = "") -> None:
        """Record an authorisation failure seen on any endpoint.

        Detection lives here rather than only in the transport's exception
        handler so it depends on the status code the server returned, not on how
        that status happened to reach us. A 403 is a 403 whether it arrived as an
        HTTPError, a wrapped response, or a stubbed one under test.
        """
        if status in (401, 403):
            self.permission_denied = True
            if path:
                self.permission_denied_endpoints[path] = status

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

    # -- Analysis identity ----------------------------------------------------

    def _fetch_last_analysis(
        self, project_key: str, result: ScannerResult
    ) -> Dict[str, Any]:
        """Identity of the most recent analysis: when it ran and over what code.

        Never fatal on its own. When it cannot be established the freshness check
        degrades to "unknown", which is a non-PASS state -- an unestablished
        analysis identity must not read as a current one.
        """
        identity: Dict[str, Any] = {
            "available": False,
            "date": "",
            "revision": "",
            "analysis_key": "",
            "project_version": "",
            "error": "",
        }
        payload, error = self._get_with_branch_fallback(
            "/api/project_analyses/search", {"project": project_key, "ps": 1}, result
        )
        if payload is None:
            identity["error"] = error or "no response"
            result.warnings.append(
                "The date and revision of the last SonarQube analysis could not be retrieved (%s). "
                "Result freshness is therefore NOT_ESTABLISHED." % identity["error"]
            )
            return identity

        analyses = payload.get("analyses") or []
        if not analyses:
            identity["error"] = "the server reports no analysis for this project"
            result.warnings.append(
                "SonarQube holds no analysis for project %r. There are no results to read, so "
                "nothing about this project's static analysis can be asserted." % project_key
            )
            return identity

        latest = analyses[0] or {}
        identity.update(
            {
                "available": True,
                "date": str(latest.get("date") or ""),
                "revision": str(latest.get("revision") or ""),
                "analysis_key": str(latest.get("key") or ""),
                "project_version": str(latest.get("projectVersion") or ""),
            }
        )
        return identity

    def _fetch_measures(self, project_key: str, result: ScannerResult) -> Dict[str, Any]:
        """Project measures: coverage, duplication, size and issue counts.

        Best-effort context for the report. A metric the server does not hold is
        omitted, and the report renders anything absent as NOT_ESTABLISHED --
        never as zero.
        """
        payload, error = self._get_with_branch_fallback(
            "/api/measures/component",
            {"component": project_key, "metricKeys": ",".join(MEASURE_METRICS)},
            result,
        )
        if payload is None:
            result.warnings.append(
                "SonarQube project measures (coverage, duplication, size) could not be retrieved "
                "(%s); they are reported as NOT_ESTABLISHED." % (error or "no response")
            )
            return {}

        component = payload.get("component") or {}
        measures: Dict[str, Any] = {}
        for measure in component.get("measures") or []:
            metric = measure.get("metric")
            if not metric:
                continue
            measures[metric] = measure.get("value", measure.get("period", {}).get("value", ""))
        return measures

    def _fetch_analysed_files(self, project_key: str, result: ScannerResult) -> List[str]:
        """The files SonarQube actually holds for this project.

        Without this the framework knows SonarQube ran but not what it read, and
        the file-level census cannot credit it with a single file -- which made
        coverage read 0% whenever Semgrep failed even though a full analysis had
        succeeded. Crediting only the files that carry findings would be worse:
        it would report a clean file as unanalysed.

        `/api/components/tree` with `qualifiers=FIL` is the reporting endpoint
        that answers the question directly. Failure is non-fatal and degrades to
        "reach not declared", never to an assumed reach.
        """
        paths: List[str] = []
        page = 1
        while True:
            payload, error = self._get_with_branch_fallback(
                "/api/components/tree",
                {"component": project_key, "qualifiers": "FIL", "p": page, "ps": PAGE_SIZE},
                result,
            )
            if payload is None:
                result.warnings.append(
                    "The list of files covered by the SonarQube analysis could not be retrieved "
                    "(%s). SonarQube's file-level reach is NOT_ESTABLISHED for this run, so no "
                    "file is credited to it in the coverage census." % (error or "no response")
                )
                return []

            components = payload.get("components") or []
            for component in components:
                path = str(component.get("path") or "").strip()
                if path:
                    paths.append(path.replace("\\", "/"))

            paging = payload.get("paging") or {}
            total = int(paging.get("total") or len(paths))
            if len(paths) >= total or not components:
                break
            page += 1
            if page * PAGE_SIZE > MAX_PAGEABLE:
                result.warnings.append(
                    "The SonarQube component list was truncated at the server's %d-result paging "
                    "limit; its declared file coverage is a lower bound." % MAX_PAGEABLE
                )
                break

        return paths

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

        result.metadata["analysis_state"] = SONARQUBE_RESULT_UNAVAILABLE

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

        # 2. Analysis identity -- WHICH code do the results below describe?
        identity = self._fetch_last_analysis(project_key, result)
        payload["analysis"] = identity
        analysis_date = parse_sonar_datetime(identity.get("date", ""))
        fresh, basis, freshness_reason = evaluate_freshness(
            analysis_date,
            identity.get("revision", ""),
            self.commit,
            self.max_analysis_age_days,
        )
        payload["freshness"] = {
            "fresh": fresh,
            "basis": basis,
            "reason": freshness_reason,
            "scanned_commit": self.commit or "NOT_ESTABLISHED",
            "analysis_revision": identity.get("revision") or "NOT_ESTABLISHED",
            "analysis_date": identity.get("date") or "NOT_ESTABLISHED",
            "max_age_days": self.max_analysis_age_days,
        }
        result.metadata["analysis_date"] = identity.get("date") or "NOT_ESTABLISHED"
        result.metadata["analysis_revision"] = identity.get("revision") or "NOT_ESTABLISHED"
        result.metadata["scanned_commit"] = self.commit or "NOT_ESTABLISHED"
        result.metadata["freshness_basis"] = basis
        if not fresh:
            # A stale result is not a failed scan -- the data is real, it simply
            # does not describe this commit. PARTIAL keeps the findings in the
            # report (they are still true of the code they were produced from)
            # while denying the category a PASS it has not earned.
            result.partial(
                "SONARQUBE_RESULT_STALE: %s These findings are reported for information; they "
                "are NOT evidence about the code in this run." % freshness_reason
            )

        # 3. Quality gate -- an authoritative, explicit security signal.
        gate, gate_error = self._get_with_branch_fallback(
            "/api/qualitygates/project_status", {"projectKey": project_key}, result
        )
        if gate is None:
            result.fail("Quality gate status could not be retrieved: %s" % gate_error)
            payload["quality_gate"] = None
        else:
            payload["quality_gate"] = gate

        # 4. Project measures -- coverage, duplication, size, counts.
        payload["measures"] = self._fetch_measures(project_key, result)

        # 4b. Which files this analysis actually covered. Declared to the
        # file-level census so SonarQube is credited for the code it read, and
        # only for that code.
        analysed_files = self._fetch_analysed_files(project_key, result)
        payload["analysed_files_count"] = len(analysed_files)
        if analysed_files:
            result.metadata["coverage"] = {
                "exclusions": {"intent": "sast", "patterns": []},
                "extensions": [],
                "files": analysed_files,
                "unit": "files",
                "unit_detail": {
                    "source": "SonarQube /api/components/tree",
                    "analysis_revision": identity.get("revision") or "NOT_ESTABLISHED",
                    "analysis_date": identity.get("date") or "NOT_ESTABLISHED",
                },
            }
            result.metadata["analysed_file_count"] = len(analysed_files)

        # 5. Issues.
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

        # 6. Security hotspots (separate endpoint on modern SonarQube).
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

        # 7. Rule metadata for CWE/OWASP mapping.
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

        # --- Resolve the analysis state ------------------------------------
        # Exactly one of four, decided in strict precedence. Only
        # SONARQUBE_SCAN_COMPLETED leaves the result trustworthy, and therefore
        # only it permits the category to reach PASS.
        if self.permission_denied:
            state = SONARQUBE_PERMISSION_ERROR
            refused = sorted(self.permission_denied_endpoints)
            needed = sorted({
                ENDPOINT_PERMISSIONS.get(endpoint, "Browse on the project")
                for endpoint in refused
            }) or ["Browse on the project"]
            payload["permission_diagnosis"] = {
                "refused_endpoints": {e: self.permission_denied_endpoints[e] for e in refused},
                "permissions_required": needed,
                "likely_cause": (
                    "The token authenticates (the analysis submits successfully) but is not "
                    "authorised to READ results. A SonarQube PROJECT ANALYSIS TOKEN carries only "
                    "'Execute Analysis' and cannot read the reporting API. A User Token belonging "
                    "to an account with 'Browse' on this project is required."
                ),
            }
            result.metadata["refused_endpoints"] = refused
            result.fail(
                "SONARQUBE_PERMISSION_ERROR: the supplied token was rejected (HTTP 401/403) on %s. "
                "Required permission: %s on project %r. Note that a project ANALYSIS token can "
                "submit a scan but cannot read its results -- a User Token with 'Browse' is "
                "needed. No assertion about static analysis can be made."
                % (", ".join(refused) or "at least one endpoint", "; ".join(needed), project_key)
            )
        elif result.errors:
            state = SONARQUBE_RESULT_UNAVAILABLE
        elif not fresh:
            state = SONARQUBE_RESULT_STALE
        else:
            state = SONARQUBE_SCAN_COMPLETED

        payload["analysis_state"] = state
        payload["analysis_state_reason"] = freshness_reason
        result.metadata["analysis_state"] = state
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
    "commit", "max_analysis_age_days",
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

__all__ = [
    "SonarQubeCollector", "resolve_project_key", "redact_host", "TOOL", "CATEGORY_KEY", "SCANNER_OK",
    "parse_sonar_datetime", "evaluate_freshness", "ANALYSIS_STATES",
    "SONARQUBE_SCAN_COMPLETED", "SONARQUBE_RESULT_STALE",
    "SONARQUBE_RESULT_UNAVAILABLE", "SONARQUBE_PERMISSION_ERROR",
    "DEFAULT_MAX_ANALYSIS_AGE_DAYS", "MEASURE_METRICS",
]
