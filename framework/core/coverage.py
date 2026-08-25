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


# Why a scanner read nothing. Every scanner in the run gets exactly one of
# these, so "this scanner analysed no files" is never left to interpretation.
SCANNER_ANALYSED = "analysed"
SCANNER_UNAVAILABLE = "scanner_unavailable"
SCANNER_FAILED_TO_COMPLETE = "scanner_failed"
SCANNER_NOT_APPLICABLE = "not_applicable"
SCANNER_NO_DECLARATION = "coverage_not_declared"

# Phrases a collector uses when the tool is absent. Matching on them lets the
# census distinguish "the tool was not installed" from "the tool ran and broke",
# which are different problems with different owners.
_UNAVAILABLE_MARKERS = (
    "is not installed", "not on path", "not available", "no binary",
    "neither 'semgrep' nor 'opengrep'",
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
    # The category this scanner serves. Several collectors share a binary --
    # Checkov backs three categories -- so the tool name alone does not identify
    # a row, and three identical "checkov" lines tell the reader nothing.
    category_key: str = ""
    # Whether the collector declared a file-level reach at all. Without one, the
    # number of files it "would have read" is unknowable, and this module states
    # what it can prove rather than inventing a denominator.
    declared: bool = False
    patterns: Tuple[str, ...] = ()
    # Extensions this scanner reads. Empty tuple means "every file".
    extensions: Tuple[str, ...] = ()
    vendored_skipped: Tuple[str, ...] = ()
    # Why this scanner covered nothing, when it covered nothing.
    status: str = SCANNER_ANALYSED
    status_reason: str = ""
    # Free-form reach for scanners whose unit is not a file -- git history,
    # dependency manifests, a container image, a live URL.
    unit: str = "files"
    unit_detail: Dict[str, Any] = field(default_factory=dict)
    # An authoritative list of the exact paths this scanner read, when the
    # scanner can report one. A server that tells us precisely which files its
    # analysis covered beats any inference from extensions and patterns, so when
    # this is present it decides `reads()` on its own.
    explicit_files: Optional[frozenset] = None

    def reads(self, relative_path: str, extension: str) -> bool:
        if not self.completed:
            return False
        if self.explicit_files is not None:
            return relative_path in self.explicit_files
        if self.extensions and extension not in self.extensions:
            return False
        return not is_excluded(relative_path, self.patterns)

    def would_read(self, relative_path: str, extension: str) -> bool:
        """Reach the scanner claims, ignoring whether it actually completed.

        The difference between `would_read` and `reads` is exactly the coverage
        a failed or missing scanner cost this run, which is the number the
        report needs in order to say "20 files were not analysed because the
        scanner was unavailable".
        """
        if self.explicit_files is not None:
            return relative_path in self.explicit_files
        if self.extensions and extension not in self.extensions:
            return False
        return not is_excluded(relative_path, self.patterns)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "intent": self.intent,
            "completed": self.completed,
            "status": self.status,
            "status_reason": self.status_reason,
            "excluded_patterns": list(self.patterns),
            "vendored_skipped": list(self.vendored_skipped),
            "reads_extensions": list(self.extensions) or "all",
            "unit": self.unit,
            "unit_detail": dict(self.unit_detail),
        }


def _extension(filename: str) -> str:
    lower = filename.lower()
    if lower.startswith(".") and lower.count(".") == 1:
        # .htaccess, .gitignore -- the whole name is the type.
        return lower
    _, ext = os.path.splitext(lower)
    return ext


def _classify_scanner_status(result: Any, declared: bool) -> Tuple[str, str]:
    """Why did this scanner cover what it covered?

    The census exists to make missing coverage impossible to hide, and "nothing
    was analysed" has four very different causes: the tool was absent, the tool
    broke, the category did not apply, or the collector never declared its
    reach. Each has a different owner and a different fix, so each is named.
    """
    status = str(getattr(result, "status", "") or "").upper()
    errors = list(getattr(result, "errors", None) or ())
    warnings = list(getattr(result, "warnings", None) or ())
    blob = " ".join(errors + warnings).lower()

    if getattr(result, "is_trustworthy", False):
        if not declared:
            return SCANNER_NO_DECLARATION, (
                "The scanner completed but did not declare which files it read, so no file "
                "may be credited to it."
            )
        return SCANNER_ANALYSED, "The scanner completed and declared its reach."

    if status == "SKIPPED":
        return SCANNER_NOT_APPLICABLE, (
            warnings[0] if warnings else "The scanner was skipped for this project."
        )
    if any(marker in blob for marker in _UNAVAILABLE_MARKERS):
        return SCANNER_UNAVAILABLE, (
            errors[0] if errors else "The scanner binary was not available on this runner."
        )
    return SCANNER_FAILED_TO_COMPLETE, (
        errors[0] if errors else "The scanner did not complete successfully."
    )


def scan_coverage_from_results(scanner_results: Sequence[Any]) -> List[ScanCoverage]:
    """Read each scanner's reach off its ScannerResult.

    Every scanner in the run gets an entry, including those that never ran. A
    collector declares its reach by recording `metadata["coverage"]`; one that
    does not is credited with nothing, because an undeclared reach is not
    evidence of reach. But it still appears, with the reason it covered nothing
    -- a scanner that vanishes from the census is exactly the silent gap this
    module exists to prevent.
    """
    coverages: List[ScanCoverage] = []
    for result in scanner_results or ():
        metadata = getattr(result, "metadata", None) or {}
        declared = metadata.get("coverage")
        has_declaration = isinstance(declared, dict)
        declared = declared if has_declaration else {}

        exclusions = declared.get("exclusions") or {}
        extensions = declared.get("extensions") or []
        status, reason = _classify_scanner_status(result, has_declaration)

        coverages.append(
            ScanCoverage(
                tool=getattr(result, "tool", "") or declared.get("tool", ""),
                category_key=str(getattr(result, "category_key", "") or ""),
                declared=has_declaration,
                intent=str(exclusions.get("intent") or declared.get("intent") or ""),
                # Only a fully trustworthy scan may be credited with coverage.
                # PARTIAL means the tool itself said its reach was incomplete.
                completed=bool(getattr(result, "is_trustworthy", False)) and has_declaration,
                patterns=tuple(exclusions.get("patterns") or ()),
                extensions=tuple(str(e).lower() for e in extensions),
                vendored_skipped=tuple(exclusions.get("vendored_skipped") or ()),
                status=status,
                status_reason=reason,
                unit=str(declared.get("unit") or "files"),
                unit_detail=dict(declared.get("unit_detail") or {}),
                explicit_files=(
                    frozenset(str(p).replace("\\", "/") for p in declared["files"])
                    if isinstance(declared.get("files"), (list, tuple, set))
                    else None
                ),
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

    # Per-scanner reach. Computed over every scanner in the run, including the
    # ones that read nothing, so the report can state -- per tool -- how many
    # files it analysed, skipped, or never saw because it did not run.
    per_scanner = _per_scanner_coverage(declared, files)

    # Deduplicated: one binary can back several categories (Checkov backs three),
    # and listing it three times reads as three separate problems.
    unavailable = sorted({r["tool"] for r in per_scanner if r["status"] == SCANNER_UNAVAILABLE})
    failed = sorted({r["tool"] for r in per_scanner if r["status"] == SCANNER_FAILED_TO_COMPLETE})
    if unavailable:
        notes.append(
            "Scanner(s) NOT AVAILABLE on this runner: %s. Files those scanners would have read "
            "were not analysed by them, and their categories are NOT_VERIFIED."
            % ", ".join(sorted(unavailable))
        )
    if failed:
        notes.append(
            "Scanner(s) that did NOT complete: %s. Their categories are NOT_VERIFIED and no file "
            "is credited to them." % ", ".join(failed)
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
        "per_scanner": per_scanner,
        "scanners_unavailable": sorted(unavailable),
        "scanners_failed": sorted(failed),
        "scanners": [c.to_dict() for c in declared],
        # Every uncovered file is counted; a bounded sample is named so the
        # report can show which ones without becoming unreadable.
        "not_analysed": _named_sample(buckets, reasons),
        "by_extension": _significant_extensions(by_extension),
        "notes": notes,
        "statement": _statement(code_total, code_analysed, unanalysed_code, counts),
    }


def _per_scanner_coverage(
    coverages: Sequence[ScanCoverage], files: Sequence[str]
) -> List[Dict[str, Any]]:
    """What each individual scanner read, skipped, and could not read.

    The aggregate census answers "was any file missed by everything?". This
    answers "what did THIS scanner actually look at?" -- the question asked when
    a finding is absent and someone needs to know whether it was looked for.

    Every scanner is listed, including ones that read nothing, because the row
    that says `0 analysed -- scanner_unavailable` is the most important row in
    the table.
    """
    rows: List[Dict[str, Any]] = []

    for coverage in coverages:
        analysed = 0
        excluded = 0
        outside_capability = 0
        would_have_read = 0

        # A scanner that never declared a file-level reach has no knowable
        # denominator. Reporting "0 of 149 analysed" for OWASP ZAP would invent
        # a gap that does not exist -- ZAP does not read files at all -- and
        # inventing gaps discredits the real ones.
        if not coverage.declared:
            row = {
                "tool": coverage.tool,
                "category": coverage.category_key,
                "intent": "not_declared",
                "status": coverage.status,
                "status_reason": coverage.status_reason,
                "completed": coverage.completed,
                "unit": coverage.unit,
                "analysed": 0,
                "excluded": 0,
                "outside_capability": 0,
                "not_analysed": 0,
                "in_scope": 0,
                "file_level": False,
                "excluded_patterns": [],
                "vendored_skipped": [],
                "reads_extensions": "not_declared",
            }
            row["statement"] = _scanner_statement(row)
            rows.append(row)
            continue

        for relative in files:
            extension = _extension(os.path.basename(relative))
            if coverage.explicit_files is not None:
                # The scanner named the files it read. Anything else is simply
                # outside what it covered; we do not guess a reason on its behalf.
                if relative in coverage.explicit_files:
                    would_have_read += 1
                    if coverage.completed:
                        analysed += 1
                else:
                    outside_capability += 1
                continue
            if coverage.extensions and extension not in coverage.extensions:
                # Not this engine's file type: not a gap on its part.
                outside_capability += 1
                continue
            if is_excluded(relative, coverage.patterns):
                excluded += 1
                continue
            would_have_read += 1
            if coverage.completed:
                analysed += 1

        # The coverage this run lost because the scanner did not complete.
        not_analysed = would_have_read - analysed

        row: Dict[str, Any] = {
            "tool": coverage.tool,
            "category": coverage.category_key,
            "file_level": True,
            "intent": coverage.intent or "not_declared",
            "status": coverage.status,
            "status_reason": coverage.status_reason,
            "completed": coverage.completed,
            "unit": coverage.unit,
            "analysed": analysed,
            "excluded": excluded,
            "outside_capability": outside_capability,
            "not_analysed": not_analysed,
            "in_scope": would_have_read,
            "excluded_patterns": list(coverage.patterns),
            "vendored_skipped": list(coverage.vendored_skipped),
            "reads_extensions": list(coverage.extensions) or "all",
        }
        if coverage.unit_detail:
            row["unit_detail"] = dict(coverage.unit_detail)
        row["statement"] = _scanner_statement(row)
        rows.append(row)

    rows.sort(key=lambda r: (not r["file_level"], -r["analysed"], r["tool"], r["category"]))
    return rows


def _scanner_statement(row: Dict[str, Any]) -> str:
    """One plain sentence per scanner, so the table needs no interpreting."""
    tool = row["tool"]
    label = "%s (%s)" % (tool, row["category"]) if row.get("category") else tool

    if row["status"] == SCANNER_NOT_APPLICABLE:
        return "%s did not apply to this project: %s" % (label, row["status_reason"])

    # Without a declared reach there is no denominator, so the sentence says
    # what is true -- nothing is credited -- and does not invent a file count.
    if not row.get("file_level", True):
        if row["status"] == SCANNER_UNAVAILABLE:
            return (
                "%s was NOT available on this runner and declared no file-level reach, so the "
                "coverage it would have provided is NOT_ESTABLISHED." % label
            )
        if row["status"] == SCANNER_FAILED_TO_COMPLETE:
            return (
                "%s did NOT complete and declared no file-level reach, so the coverage it would "
                "have provided is NOT_ESTABLISHED." % label
            )
        return (
            "%s does not report file-level coverage. Its findings are reported; no file is "
            "credited to it in the census above." % label
        )

    if row["status"] == SCANNER_UNAVAILABLE:
        return (
            "%s was NOT available on this runner. %d file(s) that it would have read were "
            "therefore not analysed by it." % (label, row["not_analysed"])
        )
    if row["status"] == SCANNER_FAILED_TO_COMPLETE:
        return (
            "%s did NOT complete. %d file(s) within its scope were not analysed by it."
            % (label, row["not_analysed"])
        )
    if row["unit"] != "files":
        return "%s completed over %s." % (label, row["unit"])
    return (
        "%s analysed %d file(s); %d excluded by its own path policy; %d outside the file types "
        "it parses." % (label, row["analysed"], row["excluded"], row["outside_capability"])
    )


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
