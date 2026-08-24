"""File-level coverage: which files were read, which were not, and why.

The category model answers "which control ran". It cannot answer "was any of my
code never looked at", because a control that completes successfully over half a
repository reports exactly like one that completed over all of it.

This module closes that gap. It walks the workspace, classifies every file, and
attributes each source file to the scanners that actually read it. A file ends up
in exactly one bucket, and every bucket other than `analysed` names its reason:

    analysed                  at least one file-reading scanner completed over it
    excluded_path             matched a declared exclusion (the pattern is named)
    no_scanner_for_filetype   the framework has no engine that parses this type
    scanner_did_not_complete  the engine that would have read it failed or was absent
    not_code                  images, fonts, archives, media -- data, not source

`not_code` is a real bucket rather than a silent drop: a repository whose only
"uncovered" files are 179 JPEGs is in a very different position from one whose
uncovered files are 179 PHP scripts, and the reader must be able to tell which.

Nothing here decides a verdict. It produces evidence; the status engine and the
report decide what to do with it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..detect.detector import LANGUAGE_BY_EXTENSION
from .scanpaths import is_excluded

# Walk limits. A pathological tree must not turn the manifest into the slowest
# part of the run; both limits are reported when they bite.
MAX_DEPTH = 14
MAX_FILES = 200_000

# How many uncovered files to name individually. The count is always exact; the
# list is bounded so the report stays readable.
MAX_NAMED = 100

# Extensions a SAST engine in this framework can parse. Deliberately narrower
# than "every extension Semgrep advertises": this list drives a claim about
# coverage, so it errs towards under-claiming.
SAST_PARSEABLE = {
    ".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".kt",
    ".go", ".rb", ".php", ".rs", ".swift", ".scala", ".dart", ".vue", ".svelte",
    ".html", ".htm", ".sh", ".bash",
}

# Source-ish files that no SAST engine in this framework parses. These are the
# honest gaps -- they are code, they are shipped, and nothing reads them.
NO_ENGINE = {
    ".sql": "SQL scripts and migrations -- no engine in this framework parses SQL",
    ".ps1": "PowerShell -- no engine in this framework parses PowerShell",
    ".css": "stylesheets -- not analysed for security",
    ".scss": "stylesheets -- not analysed for security",
    ".sass": "stylesheets -- not analysed for security",
    ".less": "stylesheets -- not analysed for security",
    ".vb": "VB.NET -- no engine in this framework parses VB.NET",
    ".htaccess": "Apache per-directory configuration",
    ".conf": "server configuration",
}

# Data, not source. Excluded from the coverage claim by design, counted anyway.
NOT_CODE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".tif", ".tiff",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".min.js", ".map", ".lock", ".log", ".pyc", ".class", ".so", ".dll", ".exe",
}

BUCKET_ANALYSED = "analysed"
BUCKET_EXCLUDED = "excluded_path"
BUCKET_NO_ENGINE = "no_scanner_for_filetype"
BUCKET_SCANNER_FAILED = "scanner_did_not_complete"
BUCKET_NOT_CODE = "not_code"

BUCKETS = (
    BUCKET_ANALYSED, BUCKET_EXCLUDED, BUCKET_NO_ENGINE,
    BUCKET_SCANNER_FAILED, BUCKET_NOT_CODE,
)


@dataclass
class ScanCoverage:
    """One scanner's declared reach over the workspace.

    Built from what the collector recorded, never from what it was supposed to
    do. A scanner that did not complete contributes `completed=False` and so
    covers nothing -- its files fall to `scanner_did_not_complete` rather than
    being credited to a scan that never read them.
    """

    tool: str
    intent: str = ""
    completed: bool = False
    patterns: Tuple[str, ...] = ()
    # Extensions this scanner reads. Empty tuple means "every file".
    extensions: Tuple[str, ...] = ()
    vendored_skipped: Tuple[str, ...] = ()

    def reads(self, relative_path: str, extension: str) -> bool:
        if not self.completed:
            return False
        if self.extensions and extension not in self.extensions:
            return False
        return not is_excluded(relative_path, self.patterns)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "intent": self.intent,
            "completed": self.completed,
            "excluded_patterns": list(self.patterns),
            "vendored_skipped": list(self.vendored_skipped),
            "reads_extensions": list(self.extensions) or "all",
        }


def _extension(filename: str) -> str:
    lower = filename.lower()
    if lower.startswith(".") and lower.count(".") == 1:
        # .htaccess, .gitignore -- the whole name is the type.
        return lower
    _, ext = os.path.splitext(lower)
    return ext


def scan_coverage_from_results(scanner_results: Sequence[Any]) -> List[ScanCoverage]:
    """Read each scanner's declared reach off its ScannerResult.

    A collector opts in by recording `metadata["coverage"]`. One that does not is
    listed with `completed=False` and credited with nothing: an undeclared reach
    is not evidence of reach.
    """
    coverages: List[ScanCoverage] = []
    for result in scanner_results or ():
        metadata = getattr(result, "metadata", None) or {}
        declared = metadata.get("coverage")
        if not isinstance(declared, dict):
            continue
        exclusions = declared.get("exclusions") or {}
        extensions = declared.get("extensions") or []
        coverages.append(
            ScanCoverage(
                tool=getattr(result, "tool", "") or declared.get("tool", ""),
                intent=str(exclusions.get("intent") or declared.get("intent") or ""),
                # Only a fully trustworthy scan may be credited with coverage.
                # PARTIAL means the tool itself said its reach was incomplete.
                completed=bool(getattr(result, "is_trustworthy", False)),
                patterns=tuple(exclusions.get("patterns") or ()),
                extensions=tuple(str(e).lower() for e in extensions),
                vendored_skipped=tuple(exclusions.get("vendored_skipped") or ()),
            )
        )
    return coverages


def _walk(workspace: str) -> Tuple[List[str], List[str]]:
    """Relative paths of every file under `workspace`, plus any walk limitations."""
    files: List[str] = []
    notes: List[str] = []
    root = os.path.abspath(workspace)
    truncated = False

    for current, dirnames, filenames in os.walk(root):
        relative_dir = os.path.relpath(current, root)
        depth = 0 if relative_dir == "." else relative_dir.replace("\\", "/").count("/") + 1
        if depth >= MAX_DEPTH:
            dirnames[:] = []
            notes.append("Directory tree deeper than %d levels was not walked at %s"
                         % (MAX_DEPTH, relative_dir.replace("\\", "/")))
            continue
        # .git is walked by nothing and would dominate the census.
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for filename in filenames:
            if len(files) >= MAX_FILES:
                truncated = True
                break
            path = os.path.join(current, filename)
            relative = os.path.relpath(path, root).replace("\\", "/")
            files.append(relative)
        if truncated:
            break

    if truncated:
        notes.append(
            "Workspace contains more than %d files; the census was truncated and the "
            "coverage figures below are therefore a lower bound." % MAX_FILES
        )
    return files, notes


def build_manifest(
    workspace: str,
    scanner_results: Sequence[Any] = (),
    languages: Sequence[str] = (),
) -> Dict[str, Any]:
    """Attribute every file in the workspace to a coverage bucket.

    Never raises: a manifest that cannot be built is reported as unavailable with
    the reason, because an absent manifest must not read as "everything covered".
    """
    try:
        return _build_manifest(workspace, scanner_results, languages)
    except Exception as exc:  # noqa: BLE001 - evidence collection must not break a run
        return {
            "available": False,
            "reason": "the file-coverage census did not complete: %s: %s"
                      % (type(exc).__name__, exc),
            "warning": (
                "File-level coverage is UNKNOWN for this run. This is not a statement "
                "that every file was analysed."
            ),
        }


def _build_manifest(
    workspace: str,
    scanner_results: Sequence[Any],
    languages: Sequence[str],
) -> Dict[str, Any]:
    declared = scan_coverage_from_results(scanner_results)
    files, notes = _walk(workspace)

    # Only static ANALYSIS counts toward "this file was analysed". A secret
    # scanner reads every byte of a PHP file and still says nothing about the SQL
    # injection in it; crediting it would turn the one number that matters into
    # a number that is always 100%. Its reach is reported on its own terms below.
    from .scanpaths import INTENT_SAST, INTENT_SECRET  # local: avoids a cycle at import time

    coverages = [c for c in declared if c.intent == INTENT_SAST]
    secret_coverages = [c for c in declared if c.intent == INTENT_SECRET]

    buckets: Dict[str, List[str]] = {name: [] for name in BUCKETS}
    reasons: Dict[str, str] = {}
    by_extension: Dict[str, Dict[str, int]] = {}
    covered_by: Dict[str, List[str]] = {}

    for relative in files:
        extension = _extension(os.path.basename(relative))
        stats = by_extension.setdefault(extension or "<none>", {b: 0 for b in BUCKETS})

        readers = [c.tool for c in coverages if c.reads(relative, extension)]
        if readers:
            buckets[BUCKET_ANALYSED].append(relative)
            stats[BUCKET_ANALYSED] += 1
            covered_by[relative] = readers
            continue

        if extension in NOT_CODE_EXTENSIONS:
            bucket = BUCKET_NOT_CODE
        elif any(is_excluded(relative, c.patterns) for c in coverages if c.patterns):
            bucket = BUCKET_EXCLUDED
            matched = sorted({
                pattern
                for c in coverages
                for pattern in c.patterns
                if is_excluded(relative, (pattern,))
            })
            reasons.setdefault(relative, "excluded by declared pattern(s): %s" % ", ".join(matched))
        elif extension in NO_ENGINE:
            bucket = BUCKET_NO_ENGINE
            reasons.setdefault(relative, NO_ENGINE[extension])
        elif extension in SAST_PARSEABLE or extension in LANGUAGE_BY_EXTENSION:
            # The framework HAS an engine for this file type. It was not read
            # because that engine did not complete -- the most serious bucket,
            # because it is code the project ships and expected to have covered.
            bucket = BUCKET_SCANNER_FAILED
            failed = sorted({c.tool for c in coverages if not c.completed}) or ["no scanner declared coverage"]
            reasons.setdefault(relative, "no completed scanner read this file (%s)" % ", ".join(failed))
        else:
            bucket = BUCKET_NO_ENGINE
            reasons.setdefault(relative, "unrecognised file type %r" % (extension or "<none>"))

        buckets[bucket].append(relative)
        stats[bucket] += 1

    counts = {name: len(paths) for name, paths in buckets.items()}
    # "Code" excludes data files: a repo of images must not look like a repo with
    # 40% uncovered source.
    code_total = sum(counts[b] for b in BUCKETS if b != BUCKET_NOT_CODE)
    code_analysed = counts[BUCKET_ANALYSED]
    unanalysed_code = code_total - code_analysed

    vendored_skipped = sorted({v for c in coverages for v in c.vendored_skipped})
    if vendored_skipped:
        notes.append(
            "Vendored dependency source (%s) was excluded from static analysis by design; "
            "dependency risk is covered by the SCA category."
            % ", ".join(vendored_skipped)
        )
    if not coverages:
        notes.append(
            "No static-analysis engine declared its file coverage in this run, so NO file "
            "can be shown to have been analysed. Treat the analysed count as zero, not as "
            "unknown."
        )

    secret_scanned = sorted({c.tool for c in secret_coverages if c.completed})
    if secret_scanned:
        notes.append(
            "Secret scanning (%s) read the whole tree independently of the figures above, "
            "including paths static analysis skipped. Those figures describe analysis for "
            "vulnerabilities, not for committed credentials."
            % ", ".join(secret_scanned)
        )

    return {
        "available": True,
        "workspace_files": len(files),
        "code_files": code_total,
        "code_files_analysed": code_analysed,
        "code_files_not_analysed": unanalysed_code,
        "coverage_percent": round(100.0 * code_analysed / code_total, 1) if code_total else 0.0,
        "complete": unanalysed_code == 0 and code_total > 0,
        "counts": counts,
        "secret_scanned_by": secret_scanned,
        "scanners": [c.to_dict() for c in declared],
        # Every uncovered file is counted; a bounded sample is named so the
        # report can show which ones without becoming unreadable.
        "not_analysed": _named_sample(buckets, reasons),
        "by_extension": _significant_extensions(by_extension),
        "notes": notes,
        "statement": _statement(code_total, code_analysed, unanalysed_code, counts),
    }


def _named_sample(
    buckets: Dict[str, List[str]], reasons: Dict[str, str]
) -> Dict[str, Any]:
    """Bounded, per-bucket listing of files that were not analysed."""
    out: Dict[str, Any] = {}
    for bucket in (BUCKET_SCANNER_FAILED, BUCKET_EXCLUDED, BUCKET_NO_ENGINE):
        paths = buckets[bucket]
        if not paths:
            continue
        out[bucket] = {
            "count": len(paths),
            "shown": min(len(paths), MAX_NAMED),
            "files": [
                {"file": path, "reason": reasons.get(path, "")}
                for path in sorted(paths)[:MAX_NAMED]
            ],
        }
    return out


def _significant_extensions(by_extension: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
    """Per-extension breakdown, largest first, data-only types folded away."""
    rows = []
    for extension, stats in by_extension.items():
        total = sum(stats.values())
        if extension in NOT_CODE_EXTENSIONS:
            continue
        rows.append({
            "extension": extension,
            "total": total,
            "analysed": stats[BUCKET_ANALYSED],
            "not_analysed": total - stats[BUCKET_ANALYSED],
        })
    rows.sort(key=lambda row: (-row["not_analysed"], -row["total"], row["extension"]))
    return rows


def _statement(total: int, analysed: int, unanalysed: int, counts: Dict[str, int]) -> str:
    """The sentence a reader needs, without having to interpret the numbers."""
    if total == 0:
        return "No code files were found in the workspace, so there was nothing to analyse."
    if unanalysed == 0:
        return (
            "Every one of the %d code files in the workspace was read by at least one "
            "scanner that completed successfully." % total
        )
    parts = []
    if counts.get(BUCKET_SCANNER_FAILED):
        parts.append(
            "%d because the engine that reads them did not complete"
            % counts[BUCKET_SCANNER_FAILED]
        )
    if counts.get(BUCKET_EXCLUDED):
        parts.append("%d by a declared path exclusion" % counts[BUCKET_EXCLUDED])
    if counts.get(BUCKET_NO_ENGINE):
        parts.append(
            "%d because this framework has no engine for their file type"
            % counts[BUCKET_NO_ENGINE]
        )
    return (
        "%d of %d code files were NOT read by any scanner in this run (%s). "
        "Findings in those files, if any exist, were not looked for."
        % (unanalysed, total, "; ".join(parts))
    )
