"""Shared secret and exposure detectors for framework-native scanners.

Used by the frontend bundle scanner (built artifacts) and the live JavaScript
bundle validator (deployed artifacts), so a secret that survives the build and a
secret served in production are detected by identical logic.

Every detector returns a *classification*, never the matched value. Matches are
described by pattern name, length and a non-reversible SHA-256 prefix so two
occurrences can be correlated without either being disclosed.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: Pattern[str]
    severity: str
    cwe: str
    description: str
    remediation: str


def _c(expr: str) -> Pattern[str]:
    return re.compile(expr)


DETECTORS: Tuple[Detector, ...] = (
    Detector(
        "google_api_key", _c(r"AIza[0-9A-Za-z_\-]{35}"), "HIGH", "CWE-798",
        "Google API key present in a shipped artifact",
        "Apply HTTP-referrer and API restrictions, set quota caps, then rotate. Keys that must "
        "stay server-side have to be proxied through the backend instead of shipped.",
    ),
    Detector(
        "aws_access_key_id", _c(r"AKIA[0-9A-Z]{16}"), "CRITICAL", "CWE-798",
        "AWS access key ID present in a shipped artifact",
        "Disable the key in IAM immediately, rotate it, and move credentials server-side.",
    ),
    Detector(
        "private_key_block", _c(r"-----BEGIN[A-Z ]{0,30}PRIVATE KEY-----"), "CRITICAL", "CWE-798",
        "Private key material present in a shipped artifact",
        "Rotate the key pair immediately and remove the key from the build input.",
    ),
    Detector(
        "github_token", _c(r"gh[pousr]_[0-9A-Za-z]{36}"), "CRITICAL", "CWE-798",
        "GitHub token present in a shipped artifact",
        "Revoke the token in GitHub and remove it from the build input.",
    ),
    Detector(
        "slack_token", _c(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "HIGH", "CWE-798",
        "Slack token present in a shipped artifact",
        "Revoke the token in Slack and remove it from the build input.",
    ),
    Detector(
        "jwt", _c(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "HIGH", "CWE-522",
        "JSON Web Token embedded in a shipped artifact",
        "A JWT baked into a bundle is a static credential. Remove it and issue tokens at runtime.",
    ),
    Detector(
        "assigned_secret", _c(r"(?i)(?:api[_-]?key|secret|password|passwd|pwd|token|client[_-]?secret)"
                              r"\s*[:=]\s*[\"'][A-Za-z0-9_\-/+=.]{12,}[\"']"),
        "MEDIUM", "CWE-798",
        "Hard-coded credential assignment in a shipped artifact",
        "Move the value to a server-side configuration source. Anything in a browser bundle is public.",
    ),
    Detector(
        "db_connection_string",
        _c(r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis)://[^\s\"'<>]{6,}"),
        "CRITICAL", "CWE-798",
        "Database connection string in a shipped artifact",
        "Rotate the database credential and remove all direct database access from client code.",
    ),
    Detector(
        "private_ip", _c(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
        "LOW", "CWE-200",
        "Internal/private IP address disclosed in a shipped artifact",
        "Remove internal network references from client-side code; they aid reconnaissance.",
    ),
    Detector(
        "internal_hostname",
        _c(r"(?i)\bhttps?://(?:localhost|127\.0\.0\.1|[a-z0-9\-]+\.(?:local|internal|intranet|corp))\b"),
        "LOW", "CWE-200",
        "Internal hostname disclosed in a shipped artifact",
        "Remove internal endpoints from client-side code.",
    ),
    Detector(
        "stack_trace_marker",
        _c(r"(?:at\s+[\w$.]+\s+\([^)]*:\d+:\d+\)|Traceback \(most recent call last\)|"
           r"System\.[A-Za-z.]+Exception:)"),
        "LOW", "CWE-209",
        "Stack trace or exception detail present in a shipped artifact",
        "Strip debug output from production builds; stack traces disclose internal structure.",
    ),
)

# Values that look like credentials but are placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|y{4,}|0{4,}|1234|changeme|placeholder|your[_-]?\w+|example|dummy|sample|"
    r"test|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%|__[A-Z_]+__|REDACTED|null|undefined|true|false)$"
)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Distinguishes real keys from words."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(value))
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_placeholder(value: str) -> bool:
    """True when a match is obviously not a real credential.

    Keeping false positives low matters: a scanner that cries wolf gets ignored,
    and an ignored scanner protects nothing.
    """
    stripped = value.strip().strip("\"'")
    if _PLACEHOLDER.match(stripped):
        return True
    # A long run of one repeated character is never a real key.
    if len(set(stripped)) <= 2 and len(stripped) >= 8:
        return True
    return False


def redact_reference(value: str) -> str:
    """Non-reversible reference so two occurrences can be correlated safely."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return "len=%d sha256:%s" % (len(value), digest)


@dataclass
class Match:
    detector: str
    severity: str
    cwe: str
    description: str
    remediation: str
    file: str
    line: int
    reference: str
    entropy: float


def scan_text(
    text: str,
    file_label: str,
    min_entropy_for_assigned: float = 3.0,
    max_matches_per_detector: int = 50,
) -> List[Match]:
    """Scan text for secrets and exposures. Never returns matched values."""
    matches: List[Match] = []
    if not text:
        return matches

    # Precompute line offsets once for O(log n) line lookup.
    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)

    def line_of(offset: int) -> int:
        low, high = 0, len(line_starts) - 1
        while low < high:
            mid = (low + high + 1) // 2
            if line_starts[mid] <= offset:
                low = mid
            else:
                high = mid - 1
        return low + 1

    for detector in DETECTORS:
        seen: set = set()
        count = 0
        for match in detector.pattern.finditer(text):
            value = match.group(0)
            if is_placeholder(value):
                continue

            entropy = shannon_entropy(value)
            # The generic assignment detector is the noisy one; gate it on entropy.
            if detector.name == "assigned_secret" and entropy < min_entropy_for_assigned:
                continue

            reference = redact_reference(value)
            if reference in seen:
                continue
            seen.add(reference)

            count += 1
            if count > max_matches_per_detector:
                break

            matches.append(
                Match(
                    detector=detector.name,
                    severity=detector.severity,
                    cwe=detector.cwe,
                    description=detector.description,
                    remediation=detector.remediation,
                    file=file_label,
                    line=line_of(match.start()),
                    reference=reference,
                    entropy=round(entropy, 2),
                )
            )
    return matches
