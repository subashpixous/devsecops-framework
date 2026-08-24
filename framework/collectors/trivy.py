"""Trivy collectors — dependency CVEs, container images, SBOM, Kubernetes config.

One binary serves four categories. Each mode is a separate collector so that a
failure in one never masks another.

Two deliberate choices:

  * `--scanners vuln` (or `misconfig`) is always passed explicitly. Trivy's
    built-in secret scanner is NOT used: Gitleaks owns that category, and Trivy's
    secret output embeds the raw secret value, which must never reach an
    artifact. This also satisfies the "no duplicate scanners" requirement.
  * `--exit-code` is never set, so a non-zero exit always means a real tool
    failure rather than "findings present".
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..core import scanpaths
from ..core.registry import ScannerRegistration, register_scanner
from ..core.toolrunner import accepted, run, tool_available, tool_version
from .base import Collector, ScannerResult

TOOL = "trivy"
ACCEPT_RC = (0,)
DEFAULT_TIMEOUT = 1800

CATEGORY_SCA = "sca_dependencies"
CATEGORY_IMAGE = "container_image"
CATEGORY_SBOM = "sbom"
CATEGORY_K8S = "kubernetes_security"

# Trivy is the SCA engine, so it must READ vendored dependency directories --
# for PHP (`vendor/`) and Go with no committed lockfile, that tree is the only
# record of which third-party versions are actually installed. Excluding it, as
# a shared SAST-style skip list did, made every such project report "no
# lockfile recognised" and resolve to a clean dependency scan of nothing.
#
# Misconfiguration scanning (Kubernetes manifests) has the opposite need and
# resolves its own SAST-intent plan.
def sca_exclusions(languages=()):
    return scanpaths.resolve(scanpaths.INTENT_SCA, languages)


def misconfig_exclusions(languages=()):
    return scanpaths.resolve(scanpaths.INTENT_SAST, languages)


def skip_dirs_arg(plan) -> str:
    """Trivy takes one comma-separated --skip-dirs value."""
    return ",".join(plan.patterns)


class _TrivyBase(Collector):
    """Shared plumbing: availability, execution, JSON parsing."""

    tool = TOOL

    def __init__(
        self,
        workspace: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        languages: Optional[List[str]] = None,
    ) -> None:
        self.workspace = workspace
        self.timeout = timeout
        self.languages = list(languages or ())

    def _guard(self, result: ScannerResult, what: str) -> Optional[ScannerResult]:
        if not tool_available(TOOL):
            return result.fail(
                "trivy is not installed or not on PATH. %s did NOT run, so this category "
                "is unverified." % what
            ).finish()
        result.metadata["version"] = tool_version(TOOL)
        return None

    def _run_json(self, result: ScannerResult, argv: List[str]) -> Optional[Dict[str, Any]]:
        proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
        result.metadata["tool_run"] = proc.to_dict()
        if not accepted(proc, ACCEPT_RC):
            result.fail("trivy did not complete: %s" % proc.summary()).finish()
            return None
        try:
            payload = json.loads(proc.stdout or "{}")
        except ValueError as exc:
            result.fail("trivy produced output that is not valid JSON: %s" % exc).finish()
            return None
        if not isinstance(payload, dict):
            result.fail("trivy JSON has an unexpected shape; output cannot be trusted.").finish()
            return None
        return payload


class TrivyScaCollector(_TrivyBase):
    """Dependency vulnerabilities across every detected package manager."""

    category_key = CATEGORY_SCA

    def collect(self) -> ScannerResult:
        result = self.new_result()
        plan = sca_exclusions(self.languages)
        result.metadata["exclusions"] = plan.to_dict()
        result.metadata["coverage"] = {"exclusions": plan.to_dict(), "extensions": []}
        guard = self._guard(result, "Dependency scanning")
        if guard:
            return guard

        argv = [
            TOOL, "fs",
            "--scanners", "vuln",
            "--format", "json",
            "--quiet",
            "--skip-dirs", skip_dirs_arg(plan),
            self.workspace,
        ]
        payload = self._run_json(result, argv)
        if payload is None:
            return result

        if "Results" not in payload:
            result.partial(
                "Trivy returned no 'Results' section. No lockfile, manifest or vendored "
                "package metadata was recognised anywhere under %s, so NO dependency "
                "inventory exists for this project and its dependency risk is unknown. "
                "This is not a clean dependency scan."
                % (", ".join(plan.vendored_scanned) or "the workspace")
            )
        payload["_mode"] = "fs-vuln"
        result.payload = payload
        result.metadata["result_sections"] = len(payload.get("Results") or [])
        return result.succeed().finish()


class TrivyImageCollector(_TrivyBase):
    """OS and library CVEs in a built container image."""

    category_key = CATEGORY_IMAGE

    def __init__(self, workspace: str = ".", timeout: int = DEFAULT_TIMEOUT, images: Optional[List[str]] = None) -> None:
        super().__init__(workspace=workspace, timeout=timeout)
        self.images = [i for i in (images or []) if i]

    def collect(self) -> ScannerResult:
        result = self.new_result()
        guard = self._guard(result, "Container image scanning")
        if guard:
            return guard

        if not self.images:
            return result.skip(
                "No container image reference was supplied (input 'images'). The built image was "
                "NOT scanned, so this category is unverified. Pass the image tag or digest that "
                "the build produced."
            ).finish()

        combined: Dict[str, Any] = {"_mode": "image", "_images": self.images, "Results": []}
        scanned, failed = [], []
        for image in self.images:
            argv = [TOOL, "image", "--scanners", "vuln", "--format", "json", "--quiet", image]
            proc = run(argv, timeout=self.timeout, accept_returncodes=ACCEPT_RC)
            if not accepted(proc, ACCEPT_RC):
                failed.append("%s (%s)" % (image, proc.summary()))
                continue
            try:
                payload = json.loads(proc.stdout or "{}")
            except ValueError as exc:
                failed.append("%s (invalid JSON: %s)" % (image, exc))
                continue
            for section in payload.get("Results") or []:
                section["_image"] = image
                combined["Results"].append(section)
            scanned.append(image)

        result.metadata["images_scanned"] = scanned
        result.metadata["images_failed"] = failed

        if not scanned:
            return result.fail(
                "None of the supplied images could be scanned: %s" % "; ".join(failed)
            ).finish()
        if failed:
            result.partial("Some images could not be scanned: %s" % "; ".join(failed))

        result.payload = combined
        return result.succeed().finish()


class TrivySbomCollector(_TrivyBase):
    """CycloneDX SBOM for the shipped artifact.

    This category produces an artifact, not findings. Success means the SBOM was
    generated and is well-formed.
    """

    category_key = CATEGORY_SBOM

    def __init__(
        self,
        workspace: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        images: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        super().__init__(workspace=workspace, timeout=timeout)
        self.images = [i for i in (images or []) if i]
        self.output_dir = output_dir

    def collect(self) -> ScannerResult:
        result = self.new_result()
        guard = self._guard(result, "SBOM generation")
        if guard:
            return guard

        # Prefer the shipped image; fall back to the source tree.
        if self.images:
            target_args = ["image", self.images[0]]
            target_desc = self.images[0]
        else:
            target_args = ["fs", self.workspace]
            target_desc = "filesystem:%s" % os.path.basename(os.path.abspath(self.workspace))
            result.partial(
                "No image reference supplied; the SBOM describes the source tree rather than the "
                "shipped image. Supply 'images' for an artifact-accurate SBOM."
            )

        handle, sbom_path = tempfile.mkstemp(prefix="sbom-", suffix=".cdx.json")
        os.close(handle)
        try:
            argv = [TOOL, *target_args, "--format", "cyclonedx", "--quiet", "--output", sbom_path]
            proc = run(argv, timeout=self.timeout, cwd=self.workspace, accept_returncodes=ACCEPT_RC)
            result.metadata["tool_run"] = proc.to_dict()
            if not accepted(proc, ACCEPT_RC):
                return result.fail("SBOM generation did not complete: %s" % proc.summary()).finish()

            try:
                with open(sbom_path, "r", encoding="utf-8", errors="replace") as fh:
                    sbom = json.load(fh)
            except (OSError, ValueError) as exc:
                return result.fail("SBOM was not produced or is not valid JSON: %s" % exc).finish()

            components = sbom.get("components") or []
            if not components:
                result.partial("SBOM contains zero components; dependency inventory may be incomplete.")

            # Persist the SBOM as a first-class artifact alongside the reports.
            if self.output_dir:
                try:
                    os.makedirs(self.output_dir, exist_ok=True)
                    dest = os.path.join(self.output_dir, "sbom.cdx.json")
                    with open(dest, "w", encoding="utf-8") as fh:
                        json.dump(sbom, fh, indent=2)
                    result.metadata["sbom_artifact"] = os.path.basename(dest)
                except OSError as exc:
                    result.partial("SBOM could not be written to the artifact directory: %s" % exc)

            result.payload = {
                "_mode": "sbom",
                "_target": target_desc,
                "bomFormat": sbom.get("bomFormat"),
                "specVersion": sbom.get("specVersion"),
                "component_count": len(components),
                "Results": [],  # no findings; keeps the adapter contract uniform
            }
            result.metadata["component_count"] = len(components)
            result.metadata["target"] = target_desc
            return result.succeed().finish()
        finally:
            try:
                os.unlink(sbom_path)
            except OSError:
                pass


class TrivyKubernetesCollector(_TrivyBase):
    """Misconfiguration in Kubernetes manifests."""

    category_key = CATEGORY_K8S

    def collect(self) -> ScannerResult:
        result = self.new_result()
        plan = misconfig_exclusions(self.languages)
        result.metadata["exclusions"] = plan.to_dict()
        guard = self._guard(result, "Kubernetes manifest scanning")
        if guard:
            return guard

        argv = [
            TOOL, "config",
            "--format", "json",
            "--quiet",
            "--skip-dirs", skip_dirs_arg(plan),
            self.workspace,
        ]
        payload = self._run_json(result, argv)
        if payload is None:
            return result

        payload["_mode"] = "config-k8s"
        result.payload = payload
        return result.succeed().finish()


# Each collector declares exactly which kwargs it accepts, so the shared kwarg
# bag passed by the pipeline can grow without breaking any single collector.
TrivyScaCollector.ACCEPTS = {"workspace", "timeout", "languages"}
TrivyImageCollector.ACCEPTS = {"workspace", "timeout", "images"}
TrivySbomCollector.ACCEPTS = {"workspace", "timeout", "images", "output_dir"}
TrivyKubernetesCollector.ACCEPTS = {"workspace", "timeout", "languages"}


def _factory(cls):
    def build(**kwargs: Any):
        return cls(**{k: v for k, v in kwargs.items() if k in cls.ACCEPTS})

    return build


def _adapter_factory(**_: Any) -> Any:
    from ..adapters.trivy_adapter import TrivyAdapter

    return TrivyAdapter()


for _tool_name, _cls, _cat, _desc in (
    ("trivy-sca", TrivyScaCollector, CATEGORY_SCA, "Trivy dependency vulnerability scanning."),
    ("trivy-image", TrivyImageCollector, CATEGORY_IMAGE, "Trivy container image vulnerability scanning."),
    ("trivy-sbom", TrivySbomCollector, CATEGORY_SBOM, "Trivy CycloneDX SBOM generation."),
    ("trivy-k8s", TrivyKubernetesCollector, CATEGORY_K8S, "Trivy Kubernetes manifest misconfiguration scanning."),
):
    _cls.tool = _tool_name  # type: ignore[attr-defined]
    register_scanner(
        ScannerRegistration(
            tool=_tool_name,
            category_key=_cat,
            collector_factory=_factory(_cls),
            adapter_factory=_adapter_factory,
            description=_desc,
        )
    )
