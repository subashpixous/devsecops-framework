"""Cross-scanner correlation -- corroboration without deletion.

When SonarQube and Semgrep both find the SQL injection on line 42 of `login.php`,
a naive deduplicator keeps one and drops the other. That is the wrong trade for
this framework, for two reasons:

  1. **Evidence loss.** "Two independent engines found this" is a stronger
     statement than "one engine found this", and it is exactly the statement an
     auditor wants. Deleting a row deletes that.

  2. **Suppression blast radius.** Findings are suppressed by fingerprint. Merge
     two findings into one and a single exception entry silently suppresses a
     second scanner's evidence that nobody reviewed. The fingerprint module
     already learned this lesson the hard way -- 83 of 156 findings once shared
     an identity -- and this module must not reintroduce it.

So correlation here is **additive**. Every finding keeps its own fingerprint, its
own row in `findings.csv`, and its own lifecycle. What it gains is a
`correlation_id` and a list of the other tools that independently found the same
thing, so the report can say:

    Detected by: sonarqube + semgrep

Correlation is deliberately CONSERVATIVE. Two findings are only linked when they
agree on the file AND on a shared CWE. Without a CWE on both sides there is no
link, because "two findings in the same file" is not evidence they are the same
defect, and a wrong link is worse than no link.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Set, Tuple

# How far apart two reports of the same defect may sit and still be the same
# defect. Scanners disagree by a line or two depending on whether they anchor to
# the statement, the expression or the enclosing block.
LINE_PROXIMITY = 3


def _normalise_path(value: str) -> str:
    return (value or "").strip().replace("\\", "/").lower()


def _cwes(finding: Any) -> Set[str]:
    """Every CWE a finding claims, normalised to `CWE-79` form."""
    raw = getattr(finding, "cwe", "") or ""
    out: Set[str] = set()
    for token in str(raw).replace(";", ",").split(","):
        token = token.strip().upper()
        if not token:
            continue
        if token.isdigit():
            token = "CWE-%s" % token
        if token.startswith("CWE-"):
            out.add(token)
    return out


@dataclass
class CorrelationGroup:
    """One defect, as reported by one or more scanners."""

    correlation_id: str
    file: str
    cwe: str
    tools: List[str] = field(default_factory=list)
    fingerprints: List[str] = field(default_factory=list)
    lines: List[int] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    description: str = ""

    @property
    def corroborated(self) -> bool:
        """True when more than one independent tool reported this defect."""
        return len(set(self.tools)) > 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "file": self.file,
            "cwe": self.cwe,
            "tools": sorted(set(self.tools)),
            "tool_count": len(set(self.tools)),
            "fingerprints": list(self.fingerprints),
            "lines": sorted(set(self.lines)),
            "severities": sorted(set(self.severities)),
            "description": self.description,
            "corroborated": self.corroborated,
        }


@dataclass
class CorrelationSummary:
    groups: List[CorrelationGroup] = field(default_factory=list)
    findings_correlated: int = 0
    notes: List[str] = field(default_factory=list)

    @property
    def corroborated_groups(self) -> List[CorrelationGroup]:
        return [g for g in self.groups if g.corroborated]

    def to_dict(self) -> Dict[str, Any]:
        corroborated = self.corroborated_groups
        return {
            "groups": [g.to_dict() for g in corroborated],
            "corroborated_defects": len(corroborated),
            "findings_correlated": self.findings_correlated,
            "notes": self.notes,
            "statement": self.statement(),
        }

    def statement(self) -> str:
        corroborated = self.corroborated_groups
        if not corroborated:
            return (
                "No defect in this run was independently reported by more than one scanner. "
                "Every finding rests on a single engine's evidence."
            )
        return (
            "%d defect(s) were independently reported by more than one scanner, covering %d "
            "finding(s). Both reports are retained: corroboration is evidence, and removing "
            "one source would weaken it."
            % (len(corroborated), self.findings_correlated)
        )


def correlate(findings: Sequence[Any]) -> CorrelationSummary:
    """Link findings that describe the same defect. Never removes anything.

    Findings are annotated in place with `correlation_id` and
    `also_detected_by`; the returned summary drives the report section.
    """
    summary = CorrelationSummary()

    # Bucket by (file, cwe). Only findings that agree on BOTH are candidates,
    # which is why a finding with no CWE is never correlated -- an unbounded
    # "same file" match would link a hardcoded password to an XSS.
    buckets: Dict[Tuple[str, str], List[Any]] = {}
    for finding in findings:
        path = _normalise_path(getattr(finding, "file", ""))
        if not path:
            continue
        for cwe in _cwes(finding):
            buckets.setdefault((path, cwe), []).append(finding)

    correlated_ids: Set[int] = set()

    for (path, cwe), candidates in sorted(buckets.items()):
        if len(candidates) < 2:
            continue

        # Within a bucket, split by line proximity so two genuinely different
        # XSS defects 200 lines apart in one file stay separate.
        for cluster in _cluster_by_line(candidates):
            tools = {getattr(f, "tool", "") for f in cluster}
            if len(tools) < 2:
                # One scanner reporting the same rule twice in one place is not
                # corroboration; the fingerprint discriminator already keeps
                # those distinct and they are left alone.
                continue

            seed = "%s|%s|%s" % (path, cwe, min(int(getattr(f, "line", 0) or 0) for f in cluster))
            correlation_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

            group = CorrelationGroup(
                correlation_id=correlation_id,
                file=getattr(cluster[0], "file", ""),
                cwe=cwe,
                description=str(getattr(cluster[0], "description", ""))[:300],
            )
            for finding in cluster:
                tool = getattr(finding, "tool", "")
                group.tools.append(tool)
                group.fingerprints.append(getattr(finding, "fingerprint", ""))
                group.lines.append(int(getattr(finding, "line", 0) or 0))
                group.severities.append(getattr(finding, "severity", ""))

                # Annotate in place. The finding keeps its identity entirely --
                # this only records that something else saw it too.
                setattr(finding, "correlation_id", correlation_id)
                others = sorted(t for t in tools if t and t != tool)
                setattr(finding, "also_detected_by", others)
                correlated_ids.add(id(finding))

            summary.groups.append(group)

    summary.findings_correlated = len(correlated_ids)
    if summary.corroborated_groups:
        summary.notes.append(
            "Correlated findings are NOT merged or removed. Each keeps its own fingerprint, its "
            "own row in findings.csv and its own lifecycle state, so suppressing one scanner's "
            "finding never silently suppresses another's."
        )
    return summary


def _cluster_by_line(findings: Sequence[Any]) -> List[List[Any]]:
    """Split same-file, same-CWE findings into line-proximity clusters."""
    ordered = sorted(findings, key=lambda f: int(getattr(f, "line", 0) or 0))
    clusters: List[List[Any]] = []
    current: List[Any] = []
    previous = None

    for finding in ordered:
        line = int(getattr(finding, "line", 0) or 0)
        # Line 0 means "the scanner did not report a line". Those correlate on
        # file+CWE alone, which is the best available evidence for them.
        if previous is None or line == 0 or previous == 0 or line - previous <= LINE_PROXIMITY:
            current.append(finding)
        else:
            clusters.append(current)
            current = [finding]
        previous = line

    if current:
        clusters.append(current)
    return clusters
