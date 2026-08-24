"""Repository hygiene — what the repository discloses, as opposed to what it does.

Every other scanner in this framework reads the repository as *code*. That leaves
a whole class of exposure invisible, because the files that carry it are not code
and no code scanner has an opinion about them:

  * a PHP error log committed inside the web root, fetchable at `/error_log`,
    carrying absolute paths, SQL fragments and request parameters;
  * a database dump or `.env` committed next to the application it configures;
  * user-uploaded documents -- identity documents, photographs, scans --
    committed alongside the code that received them, so that every clone of the
    repository is a copy of the personal data;
  * the missing `.gitignore` that would have prevented all three.

A SAST engine reads each of those as an opaque blob and reports nothing. The
result is a repository that passes every control while publishing its own logs
and its users' documents.

This collector enumerates what is TRACKED -- not what is present. An untracked
file on a developer's disk is not an exposure; a tracked one is in every clone,
in every fork, and in the history for good.

Nothing here reads file CONTENT. Findings reference paths, counts and sizes.
For uploaded personal data even the filenames are withheld and reported as a
per-directory aggregate: a filename like `aadhaar_front_<name>.jpg` is itself
disclosure, and this framework's reports are downloadable artifacts.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available
from .base import Collector, ScannerResult

TOOL = "repo-hygiene"
CATEGORY_KEY = "repo_hygiene"
ACCEPT_RC = (0,)
DEFAULT_TIMEOUT = 120

# Directory names that are served directly by a web server. A file under one of
# these is reachable over HTTP unless something explicitly denies it.
WEB_ROOT_DIRS = {"public", "public_html", "www", "htdocs", "web", "wwwroot", "dist", "static"}

# Directory names that hold what users uploaded.
UPLOAD_DIRS = {"uploads", "upload", "storage", "files", "documents", "attachments", "media", "photos"}

# Directory names that hold content the PROJECT ships, not content users sent.
# A path passing through one of these is a static asset however it is named
# further down: `public/assets/files/guidelines.pdf` is a published document, not
# a submission, and reporting it as a personal-data breach would be a false
# positive on the most severe finding this collector can raise. One of those is
# enough for a team to stop believing the real ones.
STATIC_ASSET_DIRS = {"assets", "static", "dist", "build", "node_modules", "vendor", "fonts", "icons", "css", "js"}

# Runtime output that should never be committed.
LOG_NAMES = {"error_log", "access_log", "debug.log", "php_errors.log", "laravel.log"}
LOG_SUFFIXES = (".log",)

# Database state.
DUMP_SUFFIXES = (".sql", ".dump", ".bak", ".sqlite", ".sqlite3", ".db", ".mdb")

# Key material and environment files. Presence alone is the finding; the content
# is never opened.
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".asc")
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc"}
ENV_PREFIXES = (".env",)
ENV_ALLOWED = {".env.example", ".env.sample", ".env.template", ".env.dist"}

# Documents and images that, inside an upload directory, are user-submitted data.
DOCUMENT_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".rtf",
)

ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".rar", ".7z")


def _segments(relative: str) -> List[str]:
    return [s for s in relative.replace("\\", "/").split("/") if s and s != "."]


def under_web_root(relative: str) -> bool:
    """True when any parent directory is served directly by a web server."""
    return any(segment.lower() in WEB_ROOT_DIRS for segment in _segments(relative)[:-1])


def under_upload_dir(relative: str) -> bool:
    """True when a file sits in a directory that receives user submissions.

    A path through a static-asset directory is excluded regardless of what it is
    called below that point: those files are shipped BY the project, not sent TO
    it, and the distinction is the whole difference between a published PDF and
    a disclosed identity document.
    """
    parents = [segment.lower() for segment in _segments(relative)[:-1]]
    if any(segment in STATIC_ASSET_DIRS for segment in parents):
        return False
    return any(segment in UPLOAD_DIRS for segment in parents)


def upload_root(relative: str) -> str:
    """Deepest recognised upload directory containing this file.

    The finding is reported against this directory rather than the individual
    file, so a per-application subdirectory full of identity documents is
    summarised without naming any of them.
    """
    parts = _segments(relative)[:-1]
    for index in range(len(parts) - 1, -1, -1):
        if parts[index].lower() in UPLOAD_DIRS:
            return "/".join(parts[: index + 1])
    return "/".join(parts)


class RepoHygieneCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY

    def __init__(self, workspace: str = ".", timeout: int = DEFAULT_TIMEOUT) -> None:
        self.workspace = workspace
        self.timeout = timeout

    # -- tracked-file enumeration -------------------------------------------

    def _tracked_files(self, result: ScannerResult) -> Optional[List[str]]:
        """Paths git is tracking, or None when that cannot be established.

        The working tree is deliberately NOT used as a fallback. Untracked files
        are not an exposure, so a filesystem walk would invent findings for build
        output and local scratch files -- and the resulting noise is exactly what
        makes a control get switched off.
        """
        if not os.path.isdir(os.path.join(self.workspace, ".git")):
            result.fail(
                "The workspace is not a git repository, so the set of tracked files cannot "
                "be established. Repository hygiene was NOT assessed."
            )
            return None
        if not tool_available("git"):
            result.fail(
                "git is not installed or not on PATH, so tracked files could not be listed. "
                "Repository hygiene was NOT assessed."
            )
            return None

        proc = run(["git", "ls-files", "-z"], timeout=self.timeout,
                   cwd=self.workspace, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()
        if not accepted(proc, ACCEPT_RC):
            result.fail("git ls-files did not complete: %s" % proc.summary())
            return None

        files = [f.replace("\\", "/") for f in (proc.stdout or "").split("\0") if f.strip()]
        return files

    # -- checks --------------------------------------------------------------

    def collect(self) -> ScannerResult:  # noqa: C901 - a linear sequence of independent checks
        result = self.new_result()
        files = self._tracked_files(result)
        if files is None:
            return result.finish()

        result.metadata["tracked_files"] = len(files)
        issues: List[Dict[str, Any]] = []

        issues.extend(self._check_ignore_file(files))
        issues.extend(self._check_logs(files))
        issues.extend(self._check_dumps(files))
        issues.extend(self._check_secrets_by_name(files))
        issues.extend(self._check_uploaded_data(files))
        issues.extend(self._check_archives(files))

        result.payload = {"issues": issues, "tracked_file_count": len(files)}
        result.metadata["issue_count"] = len(issues)
        return result.succeed().finish()

    def _check_ignore_file(self, files: List[str]) -> List[Dict[str, Any]]:
        if any(f == ".gitignore" or f.endswith("/.gitignore") for f in files):
            return []
        return [{
            "rule": "missing-gitignore",
            "severity": "MEDIUM",
            "file": ".gitignore",
            "count": 1,
            "title": "The repository has no .gitignore",
            "description": (
                "No .gitignore is tracked anywhere in the repository. Nothing prevents build "
                "output, runtime logs, local configuration, database dumps or user uploads "
                "from being committed, and the other findings in this category are the "
                "direct consequence."
            ),
            "impact": (
                "Every file a developer creates in the working tree is a candidate for "
                "accidental commit, including credentials and personal data. Once committed "
                "the file remains in history even after deletion."
            ),
            "remediation": (
                "Add a .gitignore covering runtime logs, local environment files, database "
                "dumps, dependency directories, build output and upload/storage paths before "
                "the next commit."
            ),
        }]

    def _check_logs(self, files: List[str]) -> List[Dict[str, Any]]:
        issues = []
        for path in files:
            name = os.path.basename(path).lower()
            if name not in LOG_NAMES and not name.endswith(LOG_SUFFIXES):
                continue
            exposed = under_web_root(path)
            issues.append({
                "rule": "committed-runtime-log-in-webroot" if exposed else "committed-runtime-log",
                "severity": "HIGH" if exposed else "LOW",
                "file": path,
                "count": 1,
                "title": (
                    "Runtime log committed inside the web root" if exposed
                    else "Runtime log committed to the repository"
                ),
                "description": (
                    "%s is tracked in git and sits under a directory served directly by the "
                    "web server, so it is retrievable over HTTP by anyone who requests its "
                    "path. Application error logs routinely contain absolute filesystem "
                    "paths, database error text including fragments of SQL, and request "
                    "parameters." % path
                ) if exposed else (
                    "%s is a runtime log tracked in git. It is not reachable over HTTP from "
                    "this location, but it does not belong in version control." % path
                ),
                "impact": (
                    "Direct information disclosure to any unauthenticated visitor: internal "
                    "paths, software versions and database structure, which together shorten "
                    "the reconnaissance step of an attack."
                ) if exposed else "Internal detail is published to everyone with repository access.",
                "remediation": (
                    "Delete the file from the repository, add its path to .gitignore, and "
                    "configure the application to write logs outside the web root. Purge it "
                    "from history if the log contains request data. Deny access to *.log at "
                    "the web server as a defence in depth."
                ),
            })
        return issues

    def _check_dumps(self, files: List[str]) -> List[Dict[str, Any]]:
        issues = []
        for path in files:
            if not path.lower().endswith(DUMP_SUFFIXES):
                continue
            exposed = under_web_root(path)
            # Schema and migration files are a normal, intended part of a
            # repository. Only their reachability over HTTP is a finding.
            if not exposed:
                continue
            issues.append({
                "rule": "database-file-in-webroot",
                "severity": "HIGH",
                "file": path,
                "count": 1,
                "title": "Database file served from the web root",
                "description": (
                    "%s sits under a directory served directly by the web server. Schema "
                    "files disclose the full data model; dumps and embedded databases "
                    "disclose the data itself." % path
                ),
                "impact": (
                    "An unauthenticated request for this path returns the file. For a dump or "
                    "an embedded database that is a complete data breach; for a schema it is "
                    "a precise map for crafting injection payloads."
                ),
                "remediation": (
                    "Move database files outside the web root, and deny the extension at the "
                    "web server. If a dump containing real rows was ever committed, treat the "
                    "data as disclosed and purge it from history."
                ),
            })
        return issues

    def _check_secrets_by_name(self, files: List[str]) -> List[Dict[str, Any]]:
        """Files whose NAME establishes what they hold. Content is never opened."""
        issues = []
        for path in files:
            name = os.path.basename(path)
            lower = name.lower()
            is_env = lower.startswith(ENV_PREFIXES) and lower not in ENV_ALLOWED
            is_key = lower.endswith(KEY_SUFFIXES) or lower in KEY_NAMES
            if not (is_env or is_key):
                continue
            issues.append({
                "rule": "environment-file-committed" if is_env else "key-material-committed",
                "severity": "CRITICAL",
                "file": path,
                "count": 1,
                "title": (
                    "Environment file committed to the repository" if is_env
                    else "Private key or credential file committed to the repository"
                ),
                "description": (
                    "%s is tracked in git. Files of this kind exist to hold credentials, and "
                    "this check reports the file itself -- its contents were not read." % path
                ),
                "impact": (
                    "Anyone with repository access, now or at any point in its history, holds "
                    "whatever this file contains. Deleting it does not revoke it."
                ),
                "remediation": (
                    "Treat every credential in this file as compromised and rotate it first. "
                    "Then remove the file from the repository, add it to .gitignore, purge it "
                    "from history, and supply the values through the deployment environment. "
                    "Rotation comes first because history is public the moment it is pushed."
                ),
            })
        return issues

    def _check_uploaded_data(self, files: List[str]) -> List[Dict[str, Any]]:
        """User-submitted documents committed alongside the application.

        Reported per directory, never per file: an upload filename can itself
        identify a person, and this report is a downloadable artifact.
        """
        by_directory: Dict[str, int] = {}
        for path in files:
            if not under_upload_dir(path):
                continue
            if not path.lower().endswith(DOCUMENT_SUFFIXES):
                continue
            root = upload_root(path)
            by_directory[root] = by_directory.get(root, 0) + 1

        if not by_directory:
            return []

        total = sum(by_directory.values())
        # One finding per top-level upload root keeps the report actionable when
        # an application creates a directory per submission.
        roots: Dict[str, int] = {}
        for directory, count in by_directory.items():
            parts = directory.split("/")
            top = "/".join(parts[: _upload_depth(parts)])
            roots[top] = roots.get(top, 0) + count

        issues = []
        for directory, count in sorted(roots.items(), key=lambda kv: -kv[1]):
            issues.append({
                "rule": "user-uploaded-documents-committed",
                "severity": "CRITICAL",
                "file": directory,
                "count": count,
                "title": "User-uploaded documents are committed to the repository",
                "description": (
                    "%d document or image files submitted through the application are tracked "
                    "in git under %s. In an application that collects identity documents, "
                    "photographs or certificates, these are the submissions themselves. "
                    "Individual filenames are withheld from this report because a filename "
                    "can identify the person who submitted it."
                    % (count, directory)
                ),
                "impact": (
                    "Every clone, fork and backup of this repository is a complete copy of "
                    "the personal data, held by everyone who has ever had read access and "
                    "retained in history after deletion. Where the documents are identity "
                    "records this is a reportable personal-data breach, not a code defect."
                ),
                "remediation": (
                    "Stop tracking the upload path: add it to .gitignore and remove it from "
                    "the index. Store submissions outside the repository -- object storage or "
                    "a mounted volume the deployment provides. Purge the existing files from "
                    "git history, rotate any credential that protected them, and follow your "
                    "jurisdiction's breach process, since the data was exposed for as long as "
                    "the repository has existed."
                ),
            })
        if len(roots) > 1:
            issues[0]["description"] += " %d such directories were found, totalling %d files." % (
                len(roots), total)
        return issues

    def _check_archives(self, files: List[str]) -> List[Dict[str, Any]]:
        issues = []
        for path in files:
            if not path.lower().endswith(ARCHIVE_SUFFIXES):
                continue
            if not under_web_root(path):
                continue
            issues.append({
                "rule": "archive-in-webroot",
                "severity": "MEDIUM",
                "file": path,
                "count": 1,
                "title": "Archive file served from the web root",
                "description": (
                    "%s is retrievable over HTTP. Archives committed into a web root are "
                    "usually backups or a copy of the application source." % path
                ),
                "impact": (
                    "Downloading the archive can yield the application source, including "
                    "configuration files that the running application never exposes."
                ),
                "remediation": "Remove the archive from the repository and deny archive extensions at the web server.",
            })
        return issues


def _upload_depth(parts: List[str]) -> int:
    """Index just past the first recognised upload directory in a path.

    Groups `storage/uploads/app_<id>/` under `storage/uploads` so a per-submission
    directory layout produces one finding rather than hundreds.
    """
    for index, part in enumerate(parts):
        if part.lower() in UPLOAD_DIRS:
            return index + 1
    return len(parts)


_KW = {"workspace", "timeout"}


def _build_collector(**kwargs: Any) -> RepoHygieneCollector:
    return RepoHygieneCollector(**{k: v for k, v in kwargs.items() if k in _KW})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.repo_hygiene_adapter import RepoHygieneAdapter

    return RepoHygieneAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Committed logs, dumps, key material and user-uploaded personal data.",
    )
)
