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
    """Import modules that self-register.

    Imported lazily so that a broken optional scanner cannot prevent the
    framework from starting up and producing a NOT_VERIFIED report.
    """
    from ..collectors import sonarqube as _sonarqube  # noqa: F401

    # Phase 2+: gitleaks, trivy, semgrep, checkov
    # Phase 3+: trivy-image, sbom, bundle-scanner, cosign
    # Phase 5+: zap, nuclei, runtime-probes
    # Phase 6+: prowler, iam-access-analyzer
