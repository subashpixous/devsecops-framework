"""Security policy: thresholds and required controls.

Policy is data, never code. A project may supply an override file; it is merged
over the bundled default so a project can never delete a required control by
omission -- only by explicitly setting it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .errors import PolicyError
from .schema import SEVERITY_ORDER

DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy", "default-policy.yml")

# Threshold sentinel: no limit for this severity.
UNLIMITED = -1


def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # noqa: WPS433 - optional dependency, imported lazily
    except ImportError as exc:  # pragma: no cover - environment specific
        raise PolicyError("PyYAML is required to load policy files: %s" % exc) from exc

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        raise PolicyError("Cannot read policy file %s: %s" % (path, exc)) from exc
    except Exception as exc:  # yaml.YAMLError and friends
        raise PolicyError("Cannot parse policy file %s: %s" % (path, exc)) from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PolicyError("Policy file %s must contain a mapping at the top level" % path)
    return data


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class Policy:
    """Resolved policy for one run."""

    name: str = "default"
    schema_version: int = 1
    active_phase: int = 1
    required_categories: List[str] = field(default_factory=list)
    severity_thresholds: Dict[str, int] = field(default_factory=dict)
    security_finding_categories: List[str] = field(default_factory=list)
    fail_on_quality_gate_error: bool = True
    hotspots_count_toward_thresholds: bool = False
    source_paths: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, override_path: Optional[str] = None, default_path: Optional[str] = None) -> "Policy":
        default_path = default_path or DEFAULT_POLICY_PATH
        if not os.path.exists(default_path):
            raise PolicyError("Bundled default policy is missing at %s" % default_path)

        data = _load_yaml(default_path)
        sources = [default_path]

        if override_path:
            if not os.path.exists(override_path):
                raise PolicyError("Policy override file not found: %s" % override_path)
            data = _deep_merge(data, _load_yaml(override_path))
            sources.append(override_path)

        thresholds = dict(data.get("severity_thresholds") or {})
        # Every canonical severity must have an explicit threshold. An omitted
        # severity defaults to UNLIMITED only for the informational levels; the
        # severe levels fail closed at zero.
        for level in SEVERITY_ORDER:
            if level not in thresholds:
                thresholds[level] = UNLIMITED if level in ("MEDIUM", "LOW", "INFO") else 0

        normalised: Dict[str, int] = {}
        for level, value in thresholds.items():
            try:
                normalised[str(level).upper()] = int(value)
            except (TypeError, ValueError) as exc:
                raise PolicyError("Threshold for %s must be an integer: %r" % (level, value)) from exc

        policy = cls(
            name=str(data.get("name") or "default"),
            schema_version=int(data.get("schema_version") or 1),
            active_phase=int(data.get("active_phase") or 1),
            required_categories=list(data.get("required_categories") or []),
            severity_thresholds=normalised,
            security_finding_categories=[
                str(item).lower() for item in (data.get("security_finding_categories") or [])
            ],
            fail_on_quality_gate_error=bool(data.get("fail_on_quality_gate_error", True)),
            hotspots_count_toward_thresholds=bool(data.get("hotspots_count_toward_thresholds", False)),
            source_paths=sources,
            raw=data,
        )

        if not policy.required_categories:
            raise PolicyError("Policy declares no required_categories; refusing to run with an empty control set")
        return policy

    def threshold_for(self, severity: str) -> int:
        return self.severity_thresholds.get(str(severity).upper(), 0)

    def is_security_finding_category(self, category: str) -> bool:
        return str(category or "").lower() in self.security_finding_categories

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "schema_version": self.schema_version,
            "active_phase": self.active_phase,
            "required_categories": self.required_categories,
            "severity_thresholds": self.severity_thresholds,
            "security_finding_categories": self.security_finding_categories,
            "fail_on_quality_gate_error": self.fail_on_quality_gate_error,
            "hotspots_count_toward_thresholds": self.hotspots_count_toward_thresholds,
            "source_paths": self.source_paths,
        }
