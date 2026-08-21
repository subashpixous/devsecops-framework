"""Manual security controls.

These cannot be detected reliably by any scanner in any phase. They are declared
permanently so no report can imply full security coverage. Their status is only
ever changed by a human recording a manual test result -- the framework itself
never marks them tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

MANUAL_NOT_TESTED = "MANUAL_NOT_TESTED"
MANUAL_TESTED_PASS = "MANUAL_TESTED_PASS"
MANUAL_TESTED_FAILED = "MANUAL_TESTED_FAILED"


@dataclass(frozen=True)
class ManualControl:
    key: str
    title: str
    why_not_automatable: str


MANUAL_CONTROLS: Tuple[ManualControl, ...] = (
    ManualControl(
        key="idor_bola",
        title="IDOR / Broken Object Level Authorization",
        why_not_automatable="Requires knowledge of which object belongs to which tenant or user; no scanner can infer the intended ownership model.",
    ),
    ManualControl(
        key="authorization_bypass",
        title="Authorization Bypass",
        why_not_automatable="Requires the intended role/permission matrix, which exists only in business requirements.",
    ),
    ManualControl(
        key="authentication_bypass",
        title="Authentication Bypass",
        why_not_automatable="Requires reasoning about the full auth state machine including token issuance, refresh and revocation.",
    ),
    ManualControl(
        key="account_takeover",
        title="Account Takeover",
        why_not_automatable="Chains password reset, session handling, MFA and enumeration weaknesses that are individually benign.",
    ),
    ManualControl(
        key="privilege_escalation",
        title="Privilege Escalation",
        why_not_automatable="Requires an authoritative model of the privilege hierarchy and legitimate elevation paths.",
    ),
    ManualControl(
        key="business_logic",
        title="Business Logic Flaws",
        why_not_automatable="Correctness is defined by domain rules that are not expressed anywhere in code or configuration.",
    ),
    ManualControl(
        key="race_conditions",
        title="Race Conditions / TOCTOU",
        why_not_automatable="Requires concurrent exploitation with timing control and knowledge of transactional intent.",
    ),
    ManualControl(
        key="payment_manipulation",
        title="Payment / Transaction Manipulation",
        why_not_automatable="Requires understanding of the intended pricing, discount and settlement rules.",
    ),
    ManualControl(
        key="attack_chains",
        title="Complex Multi-Step Attack Chains",
        why_not_automatable="Individually low-severity issues combine into a critical path only under human analysis.",
    ),
    ManualControl(
        key="advanced_ssrf_deserialization",
        title="Advanced SSRF / Deserialization",
        why_not_automatable="Exploitability depends on internal network reachability and available gadget chains at runtime.",
    ),
    ManualControl(
        key="zero_day",
        title="Zero-Day / Unknown Threats",
        why_not_automatable="By definition absent from every signature, rule set and vulnerability database.",
    ),
)


def manual_control_state() -> List[Dict[str, str]]:
    """Current state of manual controls.

    The framework has no mechanism to mark these tested, so every entry is
    MANUAL_NOT_TESTED until a human process records otherwise (Phase 6).
    """
    return [
        {
            "key": control.key,
            "title": control.title,
            "status": MANUAL_NOT_TESTED,
            "why_not_automatable": control.why_not_automatable,
        }
        for control in MANUAL_CONTROLS
    ]
