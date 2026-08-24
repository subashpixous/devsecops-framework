"""Which paths a scanner may skip -- and the record of what skipping them cost.

A scanner that silently skips a directory reports a clean result for code it
never read. That is the same failure this framework exists to prevent at the
category level, one level further down: not "which control did not run" but
"which FILE was not read by the control that did run".

Every exclusion is therefore declared here, resolved against the languages
actually present in the workspace, and returned as data so the run can state
exactly which paths were not analysed and why.

Two kinds of directory are excluded, for two different reasons:

  * BUILD OUTPUT -- generated artefacts. The source they were generated from is
    analysed, so skipping them loses no coverage. Excluding these is free.

  * VENDORED DEPENDENCIES -- third-party source committed into the tree
    (`vendor/` for PHP and Go, `Pods/` for CocoaPods). Skipping these DOES lose
    coverage, and whether that is acceptable depends on what the tool is for:

        an SCA scanner MUST read them -- for an ecosystem with no committed
        lockfile, the vendored tree is the only inventory of what is installed;

        a SAST scanner reading them yields thousands of findings in code the
        project cannot edit, which buries the findings it can.

    So the decision belongs to the caller's intent, never to a hard-coded list,
    and either way the choice is recorded rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple

# Intents a caller may declare. An unknown intent fails closed: nothing is
# excluded, so the scan is slow and noisy rather than silently narrow.
INTENT_SAST = "sast"
INTENT_SCA = "sca"
INTENT_SECRET = "secret"

# Version control and tooling state. Never contains project source.
ALWAYS_SKIP: Tuple[str, ...] = (
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".gradle", ".idea", ".vs", ".vscode",
)

# Generated output. The source is analysed, so these cost no coverage.
BUILD_OUTPUT: Tuple[str, ...] = (
    "dist", "build", "out", "bin", "obj", "target", "coverage",
    ".angular", ".next", ".nuxt", ".svelte-kit",
)

# Third-party source committed into the tree, by the language that puts it there.
# Skipping any of these is a REAL loss of coverage and is always reported.
VENDORED_BY_LANGUAGE: Dict[str, Tuple[str, ...]] = {
    "php": ("vendor",),
    "go": ("vendor",),
    "javascript": ("node_modules",),
    "typescript": ("node_modules",),
    "vue": ("node_modules",),
    "svelte": ("node_modules",),
    "python": (".venv", "venv", "env", "site-packages"),
    "ruby": ("vendor",),
    "swift": ("Pods",),
    "dart": (".dart_tool",),
}

# Applied when the language census is empty or unrecognised. Without this a
# workspace whose language could not be classified would have node_modules
# walked in full.
VENDORED_FALLBACK: Tuple[str, ...] = ("node_modules", "vendor", ".venv", "venv")

# Why each vendored directory exists, for the report. A reader should not have to
# know what `Pods` is to understand what was skipped.
_VENDOR_REASON: Dict[str, str] = {
    "vendor": "third-party source installed by the package manager (composer/go mod/bundler)",
    "node_modules": "third-party source installed by npm/yarn/pnpm",
    ".venv": "python virtual environment",
    "venv": "python virtual environment",
    "env": "python virtual environment",
    "site-packages": "installed python distributions",
    "Pods": "third-party source installed by CocoaPods",
    ".dart_tool": "dart package cache",
}


@dataclass
class ExclusionPlan:
    """What a scanner will skip, split by whether skipping costs coverage.

    `patterns` is what gets handed to the tool. The rest exists so the report can
    answer "was any real code not read, and if so which and why" without the
    reader having to reconstruct it from a command line.
    """

    intent: str
    patterns: Tuple[str, ...] = ()
    # Directories holding third-party source that this scan will NOT read.
    # Non-empty means the scan has a declared blind spot.
    vendored_skipped: Tuple[str, ...] = ()
    # Directories holding third-party source that this scan WILL read.
    vendored_scanned: Tuple[str, ...] = ()
    notes: List[str] = field(default_factory=list)

    @property
    def loses_coverage(self) -> bool:
        """True when this plan skips code the project actually ships."""
        return bool(self.vendored_skipped)

    def coverage_note(self) -> str:
        """One sentence naming the blind spot, or empty when there is none."""
        if not self.vendored_skipped:
            return ""
        described = ", ".join(
            "%s (%s)" % (name, _VENDOR_REASON.get(name, "vendored dependencies"))
            for name in self.vendored_skipped
        )
        return (
            "Third-party source was NOT analysed by this scan: %s. Findings in "
            "dependency code are therefore outside the scope of this result." % described
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "intent": self.intent,
            "patterns": list(self.patterns),
            "vendored_skipped": list(self.vendored_skipped),
            "vendored_scanned": list(self.vendored_scanned),
            "loses_coverage": self.loses_coverage,
            "coverage_note": self.coverage_note(),
            "notes": list(self.notes),
        }


def vendored_dirs_for(languages: Sequence[str]) -> Tuple[str, ...]:
    """Vendored-dependency directory names in play for these languages."""
    names: List[str] = []
    for language in languages or ():
        for name in VENDORED_BY_LANGUAGE.get(str(language).lower(), ()):
            if name not in names:
                names.append(name)
    if not names:
        return VENDORED_FALLBACK
    return tuple(names)


def resolve(
    intent: str,
    languages: Sequence[str] = (),
    include_dependencies: bool = False,
) -> ExclusionPlan:
    """Build the exclusion plan for one scan.

    `include_dependencies` lets a caller override the default for its intent --
    a project that vendors code it genuinely maintains can ask SAST to read it.
    The override is recorded either way, so the report never has to guess which
    behaviour produced the result.
    """
    vendored = vendored_dirs_for(languages)
    plan = ExclusionPlan(intent=intent)
    # Build output is generated FROM analysed source, so skipping it normally
    # costs no coverage. Two intents opt out: secret scanning, because a
    # credential baked into a built artefact is a real exposure its source may
    # not show; and an unrecognised intent, which must exclude nothing it has
    # not reasoned about.
    exclude_build_output = True

    if intent == INTENT_SCA:
        # SCA reads dependency code by definition: for PHP or Go with no
        # committed lockfile, the vendored tree is the ONLY inventory there is.
        scan_dependencies = True
        plan.notes.append(
            "SCA reads vendored dependency directories: without a committed lockfile they "
            "are the only record of which third-party versions are installed."
        )
    elif intent == INTENT_SECRET:
        # A committed credential is a committed credential wherever it sits, and
        # secret scanning is cheap. Nothing but VCS internals is skipped.
        scan_dependencies = True
        exclude_build_output = False
        plan.notes.append(
            "Secret scanning reads the entire tree: a credential committed inside a "
            "vendored directory is exposed exactly as much as one committed at the root."
        )
    elif intent == INTENT_SAST:
        scan_dependencies = bool(include_dependencies)
        if not scan_dependencies:
            plan.notes.append(
                "SAST skips vendored dependency source by default: findings in code the "
                "project cannot edit bury the findings it can. Dependency risk is covered "
                "by the SCA category, and the skipped paths are listed here."
            )
        else:
            plan.notes.append(
                "SAST was asked to include vendored dependency source (include_dependencies)."
            )
    else:
        # Unrecognised intent: exclude nothing beyond VCS internals. A slow, noisy
        # scan is recoverable; a silently narrow one is not.
        scan_dependencies = True
        exclude_build_output = False
        plan.notes.append(
            "Unrecognised scan intent %r -- nothing beyond version-control internals was "
            "excluded, so no coverage can be lost by this plan." % intent
        )

    patterns: List[str] = list(ALWAYS_SKIP)
    if exclude_build_output:
        patterns.extend(BUILD_OUTPUT)

    if scan_dependencies:
        plan.vendored_scanned = vendored
    else:
        plan.vendored_skipped = vendored
        patterns.extend(vendored)

    # Stable, de-duplicated order so the recorded plan is comparable run to run.
    seen: List[str] = []
    for pattern in patterns:
        if pattern not in seen:
            seen.append(pattern)
    plan.patterns = tuple(seen)
    return plan


def is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    """True when any path segment matches an excluded directory name.

    Segment-wise rather than substring: `vendor` must not match `vendored_ui.php`,
    and `bin` must not match `binary_upload.php`.
    """
    normalised = str(relative_path).replace("\\", "/")
    segments = [s for s in normalised.split("/") if s and s != "."]
    if not segments:
        return False
    directories = set(segments[:-1])
    patterns = set(patterns)
    return any(pattern in directories for pattern in patterns)
