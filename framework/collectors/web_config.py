"""Web server configuration — the directives that decide the exposed surface.

`.htaccess`, `nginx.conf` and `web.config` are not source code, so no SAST engine
in this framework parses them. They nevertheless decide questions that no amount
of application hardening can answer:

  * does the directory holding user uploads execute what it is given?
    An upload filter that accepts `photo.php.jpg` is a bug; a web server that
    runs any `.php` it finds in the upload directory turns that bug into remote
    code execution.
  * are directory listings served, turning an upload path into an index of every
    document ever submitted?
  * are logs, dumps, backups and version-control metadata denied, or served?

This collector reads the committed configuration and reports what it does NOT
say as well as what it does. A missing deny rule is the finding: an upload
directory with no configuration at all is the default-permissive case, and the
default is what actually runs.

It reads configuration only. No credential, no application source, no user data
is opened, and matched directives are quoted at most one line at a time.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Sequence

from ..core.registry import ScannerRegistration, register_scanner
from .base import Collector, ScannerResult

TOOL = "web-config"
CATEGORY_KEY = "web_server_config"

MAX_BYTES = 200_000
MAX_FILES = 200

UPLOAD_DIRS = {"uploads", "upload", "storage", "files", "documents", "attachments", "media", "photos"}

# Directives that stop a directory executing code it was handed.
_EXEC_GUARD = re.compile(
    r"(php_flag\s+engine\s+off"
    r"|php_admin_flag\s+engine\s+off"
    r"|RemoveHandler\s+.*\.php"
    r"|RemoveType\s+.*\.php"
    r"|SetHandler\s+(None|default-handler)"
    r"|AddType\s+text/plain\s+.*\.php"
    r"|<FilesMatch[^>]*\\\.ph"
    r"|Require\s+all\s+denied"
    r"|Deny\s+from\s+all"
    r"|location\s*~[^{]*\\\.php[^{]*\{[^}]*deny\s+all)",
    re.IGNORECASE | re.DOTALL,
)

_LISTING_ON = re.compile(r"(Options[^\n]*\+Indexes|^\s*autoindex\s+on)", re.IGNORECASE | re.MULTILINE)
_LISTING_OFF = re.compile(r"(Options[^\n]*-Indexes|^\s*autoindex\s+off)", re.IGNORECASE | re.MULTILINE)
_TOKENS_ON = re.compile(r"(ServerSignature\s+On|^\s*server_tokens\s+on)", re.IGNORECASE | re.MULTILINE)
_DENY_SENSITIVE = re.compile(r"(\\\.(log|sql|bak|env|git|ini|dump)|FilesMatch[^>]*(log|sql|bak|env))", re.IGNORECASE)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_BYTES)
    except OSError:
        return ""


def _is_upload_path(relative: str) -> bool:
    parts = [p for p in relative.replace("\\", "/").split("/") if p and p != "."]
    return any(part.lower() in UPLOAD_DIRS for part in parts)


class WebConfigCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY

    def __init__(
        self,
        workspace: str = ".",
        web_server_config_files: Optional[Sequence[str]] = None,
    ) -> None:
        self.workspace = workspace
        self.config_files = [f for f in (web_server_config_files or []) if f][:MAX_FILES]

    def collect(self) -> ScannerResult:
        result = self.new_result()
        result.metadata["config_files"] = list(self.config_files)

        if not self.config_files:
            # Applicability already established that this project has committed
            # configuration; reaching here without any means the inputs disagree.
            return result.fail(
                "No web server configuration files were supplied to this collector, so the "
                "directives governing the exposed surface were NOT reviewed."
            ).finish()

        issues: List[Dict[str, Any]] = []
        reviewed: List[str] = []
        unreadable: List[str] = []
        guarded_dirs: Dict[str, bool] = {}

        for relative in self.config_files:
            absolute = os.path.join(self.workspace, relative.replace("/", os.sep))
            content = _read(absolute)
            if not content.strip():
                unreadable.append(relative)
                continue
            reviewed.append(relative)
            directory = os.path.dirname(relative) or "."

            if _is_upload_path(relative):
                guarded_dirs[directory] = bool(_EXEC_GUARD.search(content))

            issues.extend(self._check_listing(relative, content))
            issues.extend(self._check_tokens(relative, content))
            issues.extend(self._check_upload_execution(relative, content))
            issues.extend(self._check_sensitive_files(relative, content))

        if unreadable:
            result.partial(
                "%d configuration file(s) could not be read and were NOT reviewed: %s"
                % (len(unreadable), ", ".join(unreadable[:10]))
            )

        if not reviewed:
            return result.fail(
                "None of the supplied configuration files could be read; no directive was reviewed."
            ).finish()

        result.payload = {"issues": issues, "reviewed": reviewed, "unreadable": unreadable}
        result.metadata["reviewed_count"] = len(reviewed)
        result.metadata["issue_count"] = len(issues)
        return result.succeed().finish()

    # -- individual checks ---------------------------------------------------

    def _check_upload_execution(self, relative: str, content: str) -> List[Dict[str, Any]]:
        if not _is_upload_path(relative):
            return []
        if _EXEC_GUARD.search(content):
            return []
        return [{
            "rule": "upload-directory-executes-code",
            "severity": "CRITICAL",
            "file": relative,
            "title": "Upload directory is not prevented from executing code",
            "description": (
                "%s governs a directory that receives user uploads, and contains no directive "
                "that stops the web server executing what it finds there -- no `php_flag "
                "engine off`, no handler removal, no deny rule. Any file an attacker can "
                "place in this directory with an executable extension will be run by the "
                "server when requested." % relative
            ),
            "impact": (
                "Turns any weakness in upload validation into remote code execution. Upload "
                "filters are bypassed routinely -- double extensions, content-type spoofing, "
                "null bytes, case variation -- and this directive is the control that makes "
                "such a bypass harmless instead of fatal."
            ),
            "remediation": (
                "Deny execution in the upload directory explicitly. Apache: `php_flag engine "
                "off` plus `RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phar`, or a "
                "`<FilesMatch \"\\.ph(p[0-9]?|tml|ar)$\">Require all denied</FilesMatch>`. "
                "nginx: a `location` for the upload path that denies PHP handling. Better "
                "still, store uploads outside the web root entirely and serve them through "
                "an application route that checks authorisation."
            ),
        }]

    def _check_listing(self, relative: str, content: str) -> List[Dict[str, Any]]:
        if not _LISTING_ON.search(content):
            return []
        if _LISTING_OFF.search(content):
            # Both present: later directive wins and this needs a human read.
            return [{
                "rule": "directory-listing-ambiguous",
                "severity": "LOW",
                "file": relative,
                "title": "Directory listing is both enabled and disabled in the same file",
                "description": (
                    "%s contains directives that both enable and disable directory listing. "
                    "Which applies depends on their order and scope, so the effective "
                    "behaviour cannot be determined by reading the file alone." % relative
                ),
                "impact": "The exposed surface is not established from configuration and must be confirmed against the running server.",
                "remediation": "Remove the contradiction so the configuration states the intended behaviour once.",
            }]
        return [{
            "rule": "directory-listing-enabled",
            "severity": "MEDIUM" if not _is_upload_path(relative) else "HIGH",
            "file": relative,
            "title": "Directory listing is enabled",
            "description": (
                "%s enables directory listing. A request for a directory with no index file "
                "returns a listing of everything in it." % relative
            ),
            "impact": (
                "Turns any directory into an index of its contents. Where the directory holds "
                "uploads, that is an enumerable catalogue of every document users have "
                "submitted, retrievable without knowing a single filename."
            ),
            "remediation": "Set `Options -Indexes` (Apache) or `autoindex off` (nginx) for this path.",
        }]

    def _check_tokens(self, relative: str, content: str) -> List[Dict[str, Any]]:
        if not _TOKENS_ON.search(content):
            return []
        return [{
            "rule": "server-version-disclosed",
            "severity": "LOW",
            "file": relative,
            "title": "Server software and version are disclosed in responses",
            "description": (
                "%s enables the server signature, so responses and error pages state the "
                "server software and its exact version." % relative
            ),
            "impact": (
                "Lets an attacker match the running version against public vulnerability "
                "lists without probing for it."
            ),
            "remediation": "Set `ServerSignature Off` and `ServerTokens Prod` (Apache) or `server_tokens off` (nginx).",
        }]

    def _check_sensitive_files(self, relative: str, content: str) -> List[Dict[str, Any]]:
        # Only meaningful for configuration that governs a served root.
        parts = [p for p in relative.replace("\\", "/").split("/") if p]
        served = any(p.lower() in {"public", "public_html", "www", "htdocs", "web", "wwwroot"} for p in parts)
        if not served or _DENY_SENSITIVE.search(content):
            return []
        return [{
            "rule": "sensitive-extensions-not-denied",
            "severity": "MEDIUM",
            "file": relative,
            "title": "Sensitive file types are not denied in the web root",
            "description": (
                "%s governs a directory served directly by the web server and contains no "
                "rule denying access to logs, database dumps, backups, environment files or "
                "version-control metadata. Any such file that reaches this directory is "
                "served on request." % relative
            ),
            "impact": (
                "A single misplaced `.env`, `.sql`, `.bak` or `.git` directory becomes "
                "publicly readable with no further mistake required. This rule is the "
                "backstop for exactly that."
            ),
            "remediation": (
                "Deny the extensions explicitly, for example `<FilesMatch \"\\.(env|log|sql|"
                "bak|ini|dump)$\">Require all denied</FilesMatch>` plus a deny rule for "
                "`.git`, or the equivalent nginx `location ~ /\\.` block."
            ),
        }]


_KW = {"workspace", "web_server_config_files"}


def _build_collector(**kwargs: Any) -> WebConfigCollector:
    return WebConfigCollector(**{k: v for k, v in kwargs.items() if k in _KW})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.web_config_adapter import WebConfigAdapter

    return WebConfigAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Apache/nginx/IIS directives governing execution, listing and file exposure.",
    )
)
