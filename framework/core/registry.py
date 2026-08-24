"""Scanner registry -- the Phase 2..6 extension point.

Adding a scanner means writing a Collector + Adapter and registering it here.
Nothing in the status engine, reporting layer or workflow changes. The registry
is what keeps the framework universal: the pipeline asks "which registered
scanners apply to this project in this phase", never "which project is this".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .categories import CATEGORY_BY_KEY, SecurityCategory


@dataclass(frozen=True)
class ScannerRegistration:
    """Binds a tool to a security category and its collector/adapter factories."""

    tool: str
    category_key: str
    collector_factory: Callable[..., object]
    adapter_factory: Callable[..., object]
    description: str = ""

    @property
    def category(self) -> SecurityCategory:
        return CATEGORY_BY_KEY[self.category_key]

    @property
    def phase(self) -> int:
        return self.category.phase


_REGISTRY: Dict[str, ScannerRegistration] = {}
_IMPORT_FAILURES: Dict[str, str] = {}


def register_scanner(registration: ScannerRegistration) -> ScannerRegistration:
    """Register a scanner. Re-registering the same tool replaces it."""
    if registration.category_key not in CATEGORY_BY_KEY:
        raise KeyError(
            "Scanner %r references unknown category %r; declare it in categories.py first"
            % (registration.tool, registration.category_key)
        )
    _REGISTRY[registration.tool] = registration
    return registration


def get_scanner(tool: str) -> Optional[ScannerRegistration]:
    return _REGISTRY.get(tool)


def registered_scanners() -> List[ScannerRegistration]:
    return sorted(_REGISTRY.values(), key=lambda r: (r.phase, r.tool))


def scanners_for_phase(active_phase: int) -> List[ScannerRegistration]:
    """Scanners whose category has shipped by `active_phase`."""
    return [r for r in registered_scanners() if r.phase <= active_phase]


def implemented_category_keys(active_phase: int) -> List[str]:
    """Category keys that have at least one registered scanner in this phase."""
    return sorted({r.category_key for r in scanners_for_phase(active_phase)})


def load_builtin_scanners() -> None:
    """Import every collector module so each self-registers.

    Imported inside the function, and each in its own try block, so that one
    broken or partially-installed scanner can never prevent the framework from
    starting up and producing a NOT_VERIFIED report for the rest.
    """
    modules = (
        # PRE-BUILD
        "sonarqube", "semgrep", "gitleaks", "checkov", "apispec",
        "repo_hygiene", "web_config",
        # PRE-BUILD + POST-BUILD (trivy registers four scanners)
        "trivy",
        # POST-BUILD
        "bundle_scanner", "cosign",
        # POST-DEPLOY
        "zap", "nuclei", "runtime_probes",
        # CLOUD
        "prowler", "iam_access_analyzer",
    )
    import importlib

    # framework.core -> framework
    root_package = (__package__ or "framework.core").rsplit(".", 1)[0]
    for name in modules:
        try:
            importlib.import_module("%s.collectors.%s" % (root_package, name))
        except Exception as exc:  # noqa: BLE001 - a broken scanner must not break startup
            _IMPORT_FAILURES[name] = "%s: %s" % (type(exc).__name__, exc)


def import_failures() -> Dict[str, str]:
    """Collector modules that failed to import, with the reason.

    Surfaced in the report so a scanner that silently failed to load is visible
    rather than simply absent.
    """
    return dict(_IMPORT_FAILURES)
