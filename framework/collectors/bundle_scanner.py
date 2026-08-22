"""Frontend bundle secret scanner — framework-native, no external tool.

Scans BUILT frontend output rather than source. This catches the case that
source-level scanning misses: a value that is injected at build time, or that
lives in a file a source scanner excludes, but which ends up served to every
visitor.

Anything in a browser bundle is public by definition. There is no such thing as
a secret in shipped frontend code.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..core.registry import ScannerRegistration, register_scanner
from ..core.secretpatterns import scan_text
from .base import Collector, ScannerResult

TOOL = "bundle-scanner"
CATEGORY_KEY = "frontend_bundle_secrets"

# Conventional build output directories across the supported frontend stacks.
CANDIDATE_DIRS = (
    "dist", "build", "out", "www", ".next", ".nuxt", "public/build",
    "build/web",           # Flutter web
    "wwwroot/dist",        # ASP.NET-hosted SPA
)

SCAN_EXTENSIONS = (".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".txt")
MAP_EXTENSION = ".map"

MAX_FILE_BYTES = 12 * 1024 * 1024   # skip anything implausibly large
MAX_FILES = 4000


def find_build_outputs(workspace: str, explicit: Optional[List[str]] = None) -> List[str]:
    """Locate built frontend output directories."""
    if explicit:
        return [d for d in explicit if os.path.isdir(d)]

    found: List[str] = []
    for root, dirs, _files in os.walk(workspace):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", "obj", "bin"}
        ]
        depth = root[len(workspace):].count(os.sep)
        if depth > 3:
            dirs[:] = []
            continue
        for candidate in CANDIDATE_DIRS:
            parts = candidate.split("/")
            path = os.path.join(root, *parts)
            if os.path.isdir(path) and path not in found:
                # Only count it if it actually contains web assets.
                for _r, _d, fs in os.walk(path):
                    if any(f.endswith((".js", ".html", ".css")) for f in fs):
                        found.append(path)
                        break
    return found


class BundleScannerCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"workspace", "bundle_dirs"}

    def __init__(self, workspace: str = ".", bundle_dirs: Optional[List[str]] = None) -> None:
        self.workspace = os.path.abspath(workspace)
        self.bundle_dirs = bundle_dirs or []

    def collect(self) -> ScannerResult:
        result = self.new_result()

        targets = find_build_outputs(self.workspace, self.bundle_dirs)
        result.metadata["build_dirs_searched"] = list(CANDIDATE_DIRS) if not self.bundle_dirs else self.bundle_dirs

        if not targets:
            return result.skip(
                "No built frontend output was found (looked for %s). The shipped bundle was NOT "
                "scanned, so this category is unverified. Run this stage after the frontend build, "
                "or pass 'bundle_dirs' explicitly."
                % ", ".join(CANDIDATE_DIRS)
            ).finish()

        result.metadata["build_dirs_found"] = [os.path.relpath(t, self.workspace) for t in targets]

        matches: List[Dict[str, Any]] = []
        sourcemaps: List[str] = []
        scanned_files = 0
        skipped_large = 0

        for target in targets:
            for root, _dirs, files in os.walk(target):
                for name in sorted(files):
                    path = os.path.join(root, name)
                    relative = os.path.relpath(path, self.workspace).replace("\\", "/")

                    if name.endswith(MAP_EXTENSION):
                        sourcemaps.append(relative)
                        continue
                    if not name.endswith(SCAN_EXTENSIONS):
                        continue
                    if scanned_files >= MAX_FILES:
                        result.partial(
                            "Bundle scan stopped at %d files; coverage is incomplete." % MAX_FILES
                        )
                        break
                    try:
                        if os.path.getsize(path) > MAX_FILE_BYTES:
                            skipped_large += 1
                            continue
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read()
                    except OSError as exc:
                        result.partial("Could not read %s: %s" % (relative, exc))
                        continue

                    scanned_files += 1
                    for match in scan_text(text, relative):
                        matches.append(
                            {
                                "detector": match.detector,
                                "severity": match.severity,
                                "cwe": match.cwe,
                                "description": match.description,
                                "remediation": match.remediation,
                                "file": match.file,
                                "line": match.line,
                                "reference": match.reference,
                                "entropy": match.entropy,
                            }
                        )

        if skipped_large:
            result.partial("%d file(s) exceeded the size limit and were not scanned." % skipped_large)

        result.payload = {
            "_tool": TOOL,
            "_secret_values_stripped": True,
            "scanned_files": scanned_files,
            "build_dirs": [os.path.relpath(t, self.workspace) for t in targets],
            "matches": matches,
            "sourcemaps": sourcemaps,
        }
        result.metadata["scanned_files"] = scanned_files
        result.metadata["match_count"] = len(matches)
        result.metadata["sourcemap_count"] = len(sourcemaps)

        if scanned_files == 0:
            return result.fail(
                "Build output directories were found but contained no scannable assets; "
                "the shipped bundle could not be verified."
            ).finish()

        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> BundleScannerCollector:
    return BundleScannerCollector(**{k: v for k, v in kwargs.items() if k in BundleScannerCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.bundle_adapter import BundleAdapter

    return BundleAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Framework-native secret scanning of built frontend bundles.",
    )
)
