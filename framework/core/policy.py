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


def _numeric_map(value, label, caster):
    """Coerce a policy mapping of name -> number, refusing anything else.

    A weight that silently became 0 through a typo would drop a whole dimension
    out of the readiness calculation without saying so, which is precisely the
    class of silent gap this framework exists to prevent. So it raises.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(
            "policy key %r must be a mapping, got %r" % (label, type(value).__name__)
        )
    out = {}
    for key, item in value.items():
        try:
            out[str(key)] = caster(item)
        except (TypeError, ValueError) as exc:
            raise PolicyError("%s.%s must be a number: %r" % (label, key, item)) from exc
    return out


def _positive_int(value, label):
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("%s must be an integer: %r" % (label, value)) from exc
    if number <= 0:
        raise PolicyError("%s must be greater than zero: %r" % (label, value))
    return number


def _percent(value, label):
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("%s must be a number: %r" % (label, value)) from exc
    if number < 0 or number > 100:
        raise PolicyError("%s must be between 0 and 100: %r" % (label, value))
    return number


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

    # --- Deployment readiness (data only) ---------------------------------
    # Held as plain values so a report can print the exact number that produced
    # each figure. Nothing here branches on a project.
    readiness_weights: Dict[str, float] = field(default_factory=dict)
    readiness_risk_points: Dict[str, int] = field(default_factory=dict)
    readiness_risk_points_zero_score: int = 20
    readiness_min_test_coverage: float = 0.0
    readiness_ready_threshold: float = 100.0
    readiness_min_assurance: float = 100.0
    readiness_unknown_below_assurance: float = 50.0
    conditionally_ready_permits_deployment: bool = False
    readiness_blocking_categories: List[str] = field(default_factory=list)

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

        readiness = data.get("readiness") or {}
        if not isinstance(readiness, dict):
            raise PolicyError(
                "policy key 'readiness' must be a mapping, got %r" % type(readiness).__name__
            )

        weights = _numeric_map(readiness.get("weights"), "readiness.weights", float)
        # Fail closed on the two keys the scorer cannot proceed without. A
        # missing weight would otherwise silently resolve to zero, which removes
        # a dimension from the calculation instead of scoring it.
        weights.setdefault("default", 2.0)
        weights.setdefault("required_category", 3.0)

        risk_points = _numeric_map(readiness.get("risk_points"), "readiness.risk_points", int)
        for level in SEVERITY_ORDER:
            # An unlisted severity contributes nothing rather than raising: the
            # canonical scale can gain a level without breaking every policy
            # file in existence. UNKNOWN is the exception -- it fails closed at
            # the HIGH weight, because an unclassifiable finding must never be
            # cheaper than a classified one.
            if level not in risk_points:
                risk_points[level] = risk_points.get("HIGH", 5) if level == "UNKNOWN" else 0

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
            readiness_weights=weights,
            readiness_risk_points=risk_points,
            readiness_risk_points_zero_score=_positive_int(
                readiness.get("risk_points_zero_score", 20), "readiness.risk_points_zero_score"
            ),
            readiness_min_test_coverage=_percent(
                readiness.get("min_test_coverage_percent", 0),
                "readiness.min_test_coverage_percent",
            ),
            readiness_ready_threshold=_percent(
                readiness.get("ready_threshold_percent", 100),
                "readiness.ready_threshold_percent",
            ),
            readiness_min_assurance=_percent(
                readiness.get("minimum_assurance_percent", 100),
                "readiness.minimum_assurance_percent",
            ),
            readiness_unknown_below_assurance=_percent(
                readiness.get("unknown_below_assurance_percent", 50),
                "readiness.unknown_below_assurance_percent",
            ),
            conditionally_ready_permits_deployment=bool(
                readiness.get("conditionally_ready_permits_deployment", False)
            ),
            readiness_blocking_categories=[
                str(item) for item in (readiness.get("blocking_categories") or [])
            ],
        )

        if not policy.required_categories:
            raise PolicyError("Policy declares no required_categories; refusing to run with an empty control set")
        return policy

    def threshold_for(self, severity: str) -> int:
        return self.severity_thresholds.get(str(severity).upper(), 0)

    def is_security_finding_category(self, category: str) -> bool:
        return str(category or "").lower() in self.security_finding_categories

    def readiness_weight(self, key: str, default_key: str = "default") -> float:
        """Weight for one readiness dimension.

        Resolution order: the dimension's own key, then the named fallback
        bucket, then `default`. A dimension always resolves to a weight; it is
        never dropped from the calculation because a policy file omitted it.
        """
        if key in self.readiness_weights:
            return float(self.readiness_weights[key])
        if default_key in self.readiness_weights:
            return float(self.readiness_weights[default_key])
        return float(self.readiness_weights.get("default", 1.0))

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
            "readiness": {
                "weights": self.readiness_weights,
                "risk_points": self.readiness_risk_points,
                "risk_points_zero_score": self.readiness_risk_points_zero_score,
                "min_test_coverage_percent": self.readiness_min_test_coverage,
                "ready_threshold_percent": self.readiness_ready_threshold,
                "minimum_assurance_percent": self.readiness_min_assurance,
                "unknown_below_assurance_percent": self.readiness_unknown_below_assurance,
                "conditionally_ready_permits_deployment": (
                    self.conditionally_ready_permits_deployment
                ),
                "blocking_categories": self.readiness_blocking_categories,
            },
        }
