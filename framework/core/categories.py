"""Security category matrix.

Every security category the framework will ever cover is declared here once, with
the phase that implements it and the capability that makes it applicable. A
category never disappears from the model: if it is not applicable it reports
NOT_APPLICABLE, if its phase has not shipped it reports NOT_IMPLEMENTED, and if it
should have run but did not it reports NOT_VERIFIED.

Adding a scanner in a later phase means changing `phase` here and registering a
collector -- no redesign, no per-project branching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --- Category-level status ---------------------------------------------------

CATEGORY_PASS = "PASS"
CATEGORY_FAILED = "FAILED"
CATEGORY_NOT_VERIFIED = "NOT_VERIFIED"
CATEGORY_NOT_APPLICABLE = "NOT_APPLICABLE"
CATEGORY_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

CATEGORY_STATUSES = [
    CATEGORY_PASS,
    CATEGORY_FAILED,
    CATEGORY_NOT_VERIFIED,
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_NOT_IMPLEMENTED,
]

# --- Top-level, mutually independent statuses --------------------------------

BUILD_PASS = "PASS"
BUILD_FAIL = "FAIL"
BUILD_UNKNOWN = "UNKNOWN"

DEPLOYMENT_DEPLOYED = "DEPLOYED"
DEPLOYMENT_FAILED = "FAILED"
DEPLOYMENT_SKIPPED = "SKIPPED"

SECURITY_PASS = "PASS"
SECURITY_FAILED = "FAILED"
SECURITY_NOT_VERIFIED = "NOT_VERIFIED"

RUNTIME_PASS = "PASS"
RUNTIME_FAILED = "FAILED"
RUNTIME_NOT_TESTED = "NOT_TESTED"

# --- Scanner execution status ------------------------------------------------

SCANNER_OK = "OK"
SCANNER_PARTIAL = "PARTIAL"
SCANNER_FAILED = "FAILED"
SCANNER_SKIPPED = "SKIPPED"
SCANNER_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

# Anything other than OK means the category cannot be asserted PASS.
SCANNER_TRUSTWORTHY = {SCANNER_OK}


@dataclass(frozen=True)
class SecurityCategory:
    """One security control category in the universal model."""

    key: str
    title: str
    phase: int
    applies_when: str
    tools: Tuple[str, ...] = ()
    description: str = ""
    runtime: bool = False  # contributes to RUNTIME_SECURITY rather than SECURITY


# Ordered as they appear in the approved architecture diagram.
CATEGORY_REGISTRY: Tuple[SecurityCategory, ...] = (
    # --- PRE-BUILD ---
    SecurityCategory(
        key="sast_sonarqube",
        title="Static Analysis (SonarQube)",
        phase=1,
        applies_when="always",
        tools=("sonarqube",),
        description="Quality gate plus vulnerabilities, security hotspots and bugs from the existing SonarQube server.",
    ),
    SecurityCategory(
        key="sast_semgrep",
        title="Static Analysis (Semgrep / OpenGrep)",
        phase=2,
        applies_when="always",
        tools=("semgrep", "opengrep"),
        description="Pattern-based SAST covering rules SonarQube does not implement.",
    ),
    SecurityCategory(
        key="secret_scanning",
        title="Secret Scanning",
        phase=2,
        applies_when="always",
        tools=("gitleaks",),
        description="Committed credentials, tokens and keys across the working tree and git history.",
    ),
    SecurityCategory(
        key="sca_dependencies",
        title="Dependency / SCA",
        phase=2,
        applies_when="package_manager",
        tools=("trivy",),
        description="Known vulnerabilities in third-party dependencies.",
    ),
    SecurityCategory(
        key="iac_scanning",
        title="Infrastructure as Code",
        phase=2,
        applies_when="iac",
        tools=("checkov",),
        description="Misconfiguration in Terraform / CloudFormation / ARM templates.",
    ),
    SecurityCategory(
        key="api_spec_security",
        title="API Specification Security",
        phase=5,
        applies_when="openapi",
        tools=("42crunch",),
        description="OpenAPI contract security audit.",
    ),
    # --- POST-BUILD ---
    SecurityCategory(
        key="container_image",
        title="Container Image Scanning",
        phase=3,
        applies_when="docker",
        tools=("trivy",),
        description="OS and library CVEs in built container images.",
    ),
    SecurityCategory(
        key="sbom",
        title="SBOM Generation",
        phase=3,
        applies_when="package_manager_or_docker",
        tools=("trivy", "syft"),
        description="Software bill of materials for the shipped artifact.",
    ),
    SecurityCategory(
        key="frontend_bundle_secrets",
        title="Frontend Bundle Secret Scanning",
        phase=3,
        applies_when="frontend",
        tools=("bundle-scanner",),
        description="Secrets and keys compiled into shipped browser bundles.",
    ),
    SecurityCategory(
        key="artifact_signing",
        title="Artifact Signing / Provenance",
        phase=3,
        applies_when="docker",
        tools=("cosign", "sigstore"),
        description="Signature and provenance attestation for release artifacts.",
    ),
    SecurityCategory(
        key="kubernetes_security",
        title="Kubernetes Workload Security",
        phase=3,
        applies_when="kubernetes",
        tools=("trivy", "kubescape"),
        description="Workload, RBAC and admission configuration risk.",
    ),
    # --- LIFECYCLE ---
    SecurityCategory(
        key="finding_lifecycle",
        title="Finding Lifecycle / Accepted Risk",
        phase=4,
        applies_when="always",
        tools=("framework",),
        description="Fingerprint history, exceptions and accepted-risk expiry.",
    ),
    # --- POST-DEPLOYMENT (runtime) ---
    SecurityCategory(
        key="dast_zap",
        title="Dynamic Application Security Testing",
        phase=5,
        applies_when="deployable",
        tools=("owasp-zap",),
        description="Active and passive scanning against the running application.",
        runtime=True,
    ),
    SecurityCategory(
        key="nuclei_templates",
        title="Known-Vulnerability Probing",
        phase=5,
        applies_when="deployable",
        tools=("nuclei",),
        description="Template-driven detection of known exposures on the live target.",
        runtime=True,
    ),
    SecurityCategory(
        key="runtime_probes",
        title="Runtime Security Probes",
        phase=5,
        applies_when="deployable",
        tools=("framework",),
        description="Security headers, TLS posture, exposed debug surfaces, live bundle validation.",
        runtime=True,
    ),
    # --- CLOUD ---
    SecurityCategory(
        key="cloud_posture",
        title="Cloud Security Posture",
        phase=6,
        applies_when="cloud",
        tools=("prowler",),
        description="Cloud account configuration and compliance posture.",
    ),
    SecurityCategory(
        key="iam_access_analyzer",
        title="IAM Access Analyzer",
        phase=6,
        applies_when="cloud_aws",
        tools=("aws-iam-access-analyzer",),
        description="Externally reachable IAM grants and over-permissive policies.",
    ),
)

CATEGORY_BY_KEY: Dict[str, SecurityCategory] = {c.key: c for c in CATEGORY_REGISTRY}


@dataclass
class CategoryOutcome:
    """Resolved state of one category for one run."""

    key: str
    title: str
    phase: int
    status: str
    tools: List[str] = field(default_factory=list)
    reason: str = ""
    notes: List[str] = field(default_factory=list)
    finding_count: int = 0
    runtime: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "title": self.title,
            "phase": self.phase,
            "status": self.status,
            "tools": self.tools,
            "reason": self.reason,
            "notes": self.notes,
            "finding_count": self.finding_count,
            "runtime": self.runtime,
        }


def evaluate_applicability(
    category: SecurityCategory, capabilities: Dict[str, object]
) -> Tuple[bool, str, Optional[str]]:
    """Decide whether a category applies to this project.

    Returns (applicable, reason, blocking_note). `blocking_note` records a
    condition that will obstruct the category when its phase does ship -- it is
    carried into the report so the obstacle is never silently lost.
    """
    rule = category.applies_when

    if rule == "always":
        return True, "applies to all projects", None

    if rule == "docker":
        value = bool(capabilities.get("docker"))
        return value, "docker=%s" % value, None

    if rule == "iac":
        value = bool(capabilities.get("iac"))
        return value, "iac=%s" % value, None

    if rule == "kubernetes":
        value = bool(capabilities.get("kubernetes"))
        return value, "kubernetes=%s" % value, None

    if rule == "openapi":
        value = bool(capabilities.get("openapi"))
        note = None
        if value and not capabilities.get("openapi_spec_files"):
            note = (
                "OpenAPI is served at runtime but no static specification file is committed; "
                "a spec must be generated at build time or fetched from a running instance."
            )
        return value, "openapi=%s" % value, note

    if rule == "frontend":
        value = bool(capabilities.get("frontend"))
        return value, "frontend=%s" % value, None

    if rule == "package_manager":
        value = bool(capabilities.get("package_manager"))
        return value, "package_manager=%s" % (capabilities.get("package_manager") or []), None

    if rule == "package_manager_or_docker":
        value = bool(capabilities.get("package_manager")) or bool(capabilities.get("docker"))
        return value, "package_manager or docker present=%s" % value, None

    if rule == "cloud":
        value = bool(capabilities.get("cloud"))
        return value, "cloud=%r" % (capabilities.get("cloud") or ""), None

    if rule == "cloud_aws":
        value = str(capabilities.get("cloud") or "").lower() == "aws"
        return value, "cloud=%r" % (capabilities.get("cloud") or ""), None

    if rule == "deployable":
        # A deployed application is always in scope for runtime testing. An unknown
        # URL does NOT make it inapplicable -- that would be a silent gap. It is
        # applicable and blocked, and the blocker is recorded.
        value = bool(capabilities.get("backend")) or bool(capabilities.get("frontend"))
        note = None
        if value and not capabilities.get("deployed_url"):
            note = "deployed_url is NOT_ESTABLISHED; runtime testing cannot target this application until it is supplied."
        if value and not capabilities.get("authenticated_testing_available"):
            extra = "authenticated_testing_available is NOT_ESTABLISHED; unauthenticated coverage only."
            note = extra if note is None else note + " " + extra
        return value, "deployable=%s" % value, note

    # Unknown rule: fail closed. Applicable, so it must resolve to a real status
    # rather than vanishing from the model.
    return True, "unrecognised applicability rule %r -- failing closed" % rule, (
        "Applicability rule %r is not implemented; category retained as applicable." % rule
    )
