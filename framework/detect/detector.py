"""Universal project detection.

Inspects repository signals and emits a capabilities document. It contains no
project names and no per-project branches: every downstream decision -- which
categories apply, which scanners run -- derives from this output.

Detection is evidence-based. Anything that cannot be established from repository
content stays empty and is rendered as NOT_ESTABLISHED. Nothing is assumed.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set

IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "dist", "build",
    "out", "bin", "obj", ".angular", ".next", ".nuxt", ".svelte-kit", "vendor",
    ".venv", "venv", "env", "__pycache__", ".pytest_cache", "coverage",
    "target", ".gradle", ".idea", ".vs", ".vscode", "Pods", ".dart_tool",
}

MAX_DEPTH = 12
MAX_PROBE_BYTES = 200_000

LANGUAGE_BY_EXTENSION = {
    ".cs": "csharp", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".py": "python", ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".dart": "dart", ".swift": "swift",
    ".scala": "scala", ".vb": "vbnet", ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".vue": "vue", ".svelte": "svelte", ".sql": "sql", ".sh": "shell",
    ".ps1": "powershell",
}

# Source extensions only: assets and generated content are excluded from the
# language census so a repository is not classified by its images.
SOURCE_EXTENSIONS = set(LANGUAGE_BY_EXTENSION)

_K8S_PATTERN = re.compile(r"^\s*apiVersion\s*:", re.MULTILINE)
_K8S_KIND_PATTERN = re.compile(r"^\s*kind\s*:\s*\S+", re.MULTILINE)
_CFN_PATTERN = re.compile(r"AWSTemplateFormatVersion|Type\s*:\s*['\"]?AWS::", re.MULTILINE)
_ARM_PATTERN = re.compile(r"schema\.management\.azure\.com.*deploymentTemplate", re.IGNORECASE)
_OPENAPI_PATTERN = re.compile(r"^\s*[\"']?(openapi|swagger)[\"']?\s*[:=]", re.MULTILINE | re.IGNORECASE)


def _read(path: str, limit: int = MAX_PROBE_BYTES) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    text = _read(path)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        # Config files with comments/trailing commas are common (angular.json,
        # appsettings.json). A parse failure is not an error here -- the file's
        # existence is the signal we rely on.
        return None


class Detection:
    """Accumulates signals during the walk."""

    def __init__(self) -> None:
        self.languages: Set[str] = set()
        self.frameworks: Set[str] = set()
        self.package_managers: Set[str] = set()
        self.evidence: Dict[str, List[str]] = {}
        self.extension_counts: Dict[str, int] = {}
        self.docker = False
        self.docker_compose = False
        self.iac = False
        self.iac_types: Set[str] = set()
        self.kubernetes = False
        self.helm = False
        self.openapi = False
        self.openapi_spec_files: List[str] = []
        self.dockerfiles: List[str] = []
        self.ci_workflows: List[str] = []
        self.sonar_properties: List[str] = []
        self.frontend = False
        self.backend = False
        self.web_server_config_files: List[str] = []

    def note(self, key: str, item: str) -> None:
        self.evidence.setdefault(key, [])
        if item not in self.evidence[key] and len(self.evidence[key]) < 25:
            self.evidence[key].append(item)


def _classify_manifest(detection: Detection, root: str, filename: str, relative: str, workspace: str) -> None:
    path = os.path.join(root, filename)
    lower = filename.lower()

    if lower == "package.json":
        detection.package_managers.add("npm")
        detection.languages.add("javascript")
        detection.note("package_manager", relative)
        data = _read_json(path) or {}
        deps = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        framework_signals = {
            "@angular/core": "angular", "react": "react", "next": "nextjs",
            "vue": "vue", "nuxt": "nuxt", "svelte": "svelte",
            "express": "express", "@nestjs/core": "nestjs", "fastify": "fastify",
            "koa": "koa", "electron": "electron",
        }
        for dependency, framework in framework_signals.items():
            if dependency in deps:
                detection.frameworks.add(framework)
                detection.note("framework", "%s (%s)" % (framework, relative))
        if any(f in detection.frameworks for f in ("angular", "react", "vue", "nextjs", "nuxt", "svelte")):
            detection.frontend = True
        if any(f in detection.frameworks for f in ("express", "nestjs", "fastify", "koa")):
            detection.backend = True

    elif lower == "angular.json":
        detection.frameworks.add("angular")
        detection.frontend = True
        detection.note("framework", "angular (%s)" % relative)

    elif lower == "pubspec.yaml":
        detection.package_managers.add("pub")
        detection.languages.add("dart")
        is_flutter = "flutter" in _read(path)
        detection.frameworks.add("flutter" if is_flutter else "dart")
        # Flutter targets web as well as mobile. A committed web/ directory means
        # this project ships a browser bundle, so bundle scanning applies.
        if is_flutter and os.path.isdir(os.path.join(root, "web")):
            detection.frontend = True
            detection.note("framework", "flutter-web (%s)" % relative)
        detection.note("package_manager", relative)

    elif lower.endswith(".csproj") or lower.endswith(".vbproj"):
        detection.package_managers.add("nuget")
        detection.languages.add("csharp" if lower.endswith(".csproj") else "vbnet")
        content = _read(path)
        detection.frameworks.add("dotnet")
        if "Microsoft.NET.Sdk.Web" in content:
            detection.frameworks.add("aspnet-core")
            detection.backend = True
        if "Microsoft.NET.Sdk.BlazorWebAssembly" in content:
            detection.frontend = True
        match = re.search(r"<TargetFramework[s]?>([^<]+)</TargetFramework[s]?>", content)
        if match:
            detection.note("dotnet_target_framework", match.group(1).strip())
        detection.note("package_manager", relative)

    elif lower.endswith(".sln"):
        detection.frameworks.add("dotnet")
        detection.note("solution", relative)

    elif lower == "pom.xml":
        detection.package_managers.add("maven")
        detection.languages.add("java")
        content = _read(path)
        if "spring-boot" in content:
            detection.frameworks.add("spring-boot")
            detection.backend = True
        detection.note("package_manager", relative)

    elif lower in ("build.gradle", "build.gradle.kts"):
        detection.package_managers.add("gradle")
        detection.languages.add("java")
        content = _read(path)
        if "org.springframework.boot" in content:
            detection.frameworks.add("spring-boot")
            detection.backend = True
        if "com.android.application" in content:
            detection.frameworks.add("android")
        detection.note("package_manager", relative)

    elif lower in ("requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg"):
        detection.package_managers.add("pip")
        detection.languages.add("python")
        content = _read(path).lower()
        for needle, framework in (("django", "django"), ("flask", "flask"), ("fastapi", "fastapi")):
            if needle in content:
                detection.frameworks.add(framework)
                detection.backend = True
        detection.note("package_manager", relative)

    elif lower == "composer.json":
        detection.package_managers.add("composer")
        detection.languages.add("php")
        content = _read(path).lower()
        for needle, framework in (("laravel/framework", "laravel"), ("symfony/", "symfony")):
            if needle in content:
                detection.frameworks.add(framework)
        detection.backend = True
        detection.note("package_manager", relative)

    elif lower == "gemfile":
        detection.package_managers.add("bundler")
        detection.languages.add("ruby")
        if "rails" in _read(path).lower():
            detection.frameworks.add("rails")
            detection.backend = True
        detection.note("package_manager", relative)

    elif lower == "go.mod":
        detection.package_managers.add("gomod")
        detection.languages.add("go")
        detection.backend = True
        detection.note("package_manager", relative)

    elif lower == "cargo.toml":
        detection.package_managers.add("cargo")
        detection.languages.add("rust")
        detection.note("package_manager", relative)

    elif lower == "dockerfile" or lower.startswith("dockerfile."):
        detection.docker = True
        detection.dockerfiles.append(relative)
        detection.note("docker", relative)

    elif re.match(r"^docker-compose.*\.ya?ml$", lower) or lower == "compose.yaml":
        detection.docker = True
        detection.docker_compose = True
        detection.note("docker", relative)

    elif lower.endswith((".tf", ".tfvars")):
        detection.iac = True
        detection.iac_types.add("terraform")
        detection.note("iac", relative)

    elif lower == "chart.yaml":
        detection.kubernetes = True
        detection.helm = True
        detection.note("kubernetes", relative)

    elif lower.startswith("sonar-project.properties") or lower in (
        ".sonarcloud.properties", ".sonarqube.properties"
    ):
        detection.sonar_properties.append(relative)
        detection.note("sonarqube", relative)


# Web server configuration recognised by name. `.htaccess` carries no extension
# and `web.config` looks like any other XML, so extension-based classification
# misses both -- which is how the file that decides whether an upload directory
# executes PHP ends up read by nothing.
_WEB_CONFIG_NAMES = {
    ".htaccess", ".htpasswd", "nginx.conf", "httpd.conf", "apache2.conf",
    "web.config", "lighttpd.conf", "default.conf", "site.conf",
}

# A generic `.conf` is only server configuration if it contains server directives.
_WEB_CONFIG_MARKERS = re.compile(
    r"^\s*(server\s*\{|<VirtualHost|<Directory|location\s+[^\s{]+\s*\{|listen\s+\d)",
    re.MULTILINE | re.IGNORECASE,
)


def _classify_web_server_config(
    detection: Detection, path: str, filename: str, relative: str
) -> None:
    """Record committed Apache/nginx/IIS configuration.

    Named files are taken at face value. A generic `.conf` has to prove itself
    with a server directive, so an application's own config files are not
    mistaken for the web server's.
    """
    if len(detection.web_server_config_files) >= 200:
        return
    lower = filename.lower()
    if lower in _WEB_CONFIG_NAMES:
        detection.web_server_config_files.append(relative)
        detection.note("web_server_config", relative)
        return
    if lower.endswith((".conf", ".vhost")) and _WEB_CONFIG_MARKERS.search(_read(path, 20_000) or ""):
        detection.web_server_config_files.append(relative)
        detection.note("web_server_config", relative)


def _classify_content(detection: Detection, path: str, relative: str) -> None:
    """Content probes for formats that cannot be identified by filename alone."""
    lower = relative.lower()
    if not lower.endswith((".yml", ".yaml", ".json")):
        return

    basename = os.path.basename(lower)
    text = _read(path, 60_000)
    if not text:
        return

    if re.match(r"^(openapi|swagger)\b", basename) or _OPENAPI_PATTERN.search(text[:4000]):
        if re.search(r"[\"']?(openapi|swagger)[\"']?\s*[:=]\s*[\"']?\d", text[:4000], re.IGNORECASE):
            detection.openapi = True
            detection.openapi_spec_files.append(relative)
            detection.note("openapi", relative)
            return

    if _CFN_PATTERN.search(text[:20_000]):
        detection.iac = True
        detection.iac_types.add("cloudformation")
        detection.note("iac", relative)
        return

    if _ARM_PATTERN.search(text[:20_000]):
        detection.iac = True
        detection.iac_types.add("arm")
        detection.note("iac", relative)
        return

    if lower.endswith((".yml", ".yaml")) and _K8S_PATTERN.search(text) and _K8S_KIND_PATTERN.search(text):
        # GitHub Actions workflows also start with keys; exclude them explicitly.
        if ".github/workflows/" not in lower.replace("\\", "/"):
            detection.kubernetes = True
            detection.note("kubernetes", relative)


def _detect_cloud_and_target(workspace: str, detection: Detection) -> Dict[str, Any]:
    """Read CI workflow files for cloud and deployment-target evidence.

    Only explicit, quotable signals are used. When nothing matches, the value
    stays empty and is reported as NOT_ESTABLISHED rather than guessed.
    """
    cloud = ""
    cloud_evidence: List[str] = []
    target = ""
    target_evidence: List[str] = []
    deployed_url = ""

    workflow_dir = os.path.join(workspace, ".github", "workflows")
    if not os.path.isdir(workflow_dir):
        return {
            "cloud": cloud, "cloud_evidence": cloud_evidence,
            "deployment_target": target, "deployment_target_evidence": target_evidence,
            "deployed_url": deployed_url,
        }

    aws_signals = ("aws-actions/", "AWS_ACCESS_KEY", "AWS_REGION", "EC2_HOST", "amazon-ecr", "amazon-ecs", "eks", "aws s3", "elasticbeanstalk")
    azure_signals = ("azure/login", "azure/webapps-deploy", "AZURE_CREDENTIALS")
    gcp_signals = ("google-github-actions/", "gcloud ", "GCP_")

    for filename in sorted(os.listdir(workflow_dir)):
        if not filename.endswith((".yml", ".yaml")):
            continue
        relative = os.path.join(".github", "workflows", filename).replace("\\", "/")
        detection.ci_workflows.append(relative)
        content = _read(os.path.join(workflow_dir, filename))
        if not content:
            continue

        for signal in aws_signals:
            if signal.lower() in content.lower():
                cloud = cloud or "aws"
                cloud_evidence.append("%s: %s" % (relative, signal))
                break
        for signal in azure_signals:
            if signal.lower() in content.lower():
                cloud = cloud or "azure"
                cloud_evidence.append("%s: %s" % (relative, signal))
                break
        for signal in gcp_signals:
            if signal.lower() in content.lower():
                cloud = cloud or "gcp"
                cloud_evidence.append("%s: %s" % (relative, signal))
                break

        lowered = content.lower()
        if "amazon-ecs-deploy-task-definition" in lowered:
            target, evidence = "aws-ecs", "amazon-ecs-deploy-task-definition"
        elif "eks" in lowered and "kubectl" in lowered:
            target, evidence = "kubernetes", "kubectl + eks"
        elif "azure/webapps-deploy" in lowered:
            target, evidence = "azure-app-service", "azure/webapps-deploy"
        elif "ssh-action" in lowered or "ssh -o" in lowered:
            if "docker compose" in lowered or "docker-compose" in lowered:
                target, evidence = "ssh-host-docker-compose", "ssh-action + docker compose"
            else:
                target, evidence = "ssh-host", "ssh-action"
        elif "ftp-deploy" in lowered or "lftp" in lowered:
            target, evidence = "ftp-host", "ftp deployment action"
        else:
            evidence = ""
        if evidence:
            target_evidence.append("%s: %s" % (relative, evidence))

        url_match = re.search(r"^\s*url:\s*(https?://\S+)\s*$", content, re.MULTILINE)
        if url_match and not deployed_url:
            deployed_url = url_match.group(1).strip().strip("'\"")

    return {
        "cloud": cloud,
        "cloud_evidence": cloud_evidence,
        "deployment_target": target,
        "deployment_target_evidence": target_evidence,
        "deployed_url": deployed_url,
    }


def detect(workspace: str = ".", overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Walk the repository and emit the capabilities document."""
    workspace = os.path.abspath(workspace)
    overrides = {k: v for k, v in (overrides or {}).items() if v not in (None, "")}
    detection = Detection()

    base_depth = workspace.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(workspace):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRECTORIES)
        if root.count(os.sep) - base_depth >= MAX_DEPTH:
            dirs[:] = []

        for filename in files:
            relative = os.path.relpath(os.path.join(root, filename), workspace).replace("\\", "/")
            extension = os.path.splitext(filename)[1].lower()

            if extension in SOURCE_EXTENSIONS:
                detection.extension_counts[extension] = detection.extension_counts.get(extension, 0) + 1
                detection.languages.add(LANGUAGE_BY_EXTENSION[extension])

            _classify_manifest(detection, root, filename, relative, workspace)
            _classify_web_server_config(detection, os.path.join(root, filename), filename, relative)
            _classify_content(detection, os.path.join(root, filename), relative)

    # Frontend/backend inference from unambiguous structural signals only.
    if "html" in detection.languages and ("javascript" in detection.languages or "typescript" in detection.languages):
        detection.frontend = detection.frontend or bool(detection.frameworks & {"angular", "react", "vue", "nextjs", "nuxt", "svelte"})
    if detection.frameworks & {"aspnet-core", "spring-boot", "django", "flask", "fastapi", "express", "nestjs", "fastify", "koa", "laravel", "symfony", "rails"}:
        detection.backend = True
    if "php" in detection.languages:
        # PHP source has exactly one execution mode: interpreted by a web server
        # on request. A .php file in the tree therefore IS a server-side
        # application, framework or not -- and a framework-only rule left plain
        # PHP projects classified as "not deployable", which silently excused
        # them from every runtime security category.
        detection.backend = True
        detection.note("backend", "php sources are executed server-side")

    cloud_info = _detect_cloud_and_target(workspace, detection)

    capabilities: Dict[str, Any] = {
        # Approved capability contract
        "languages": sorted(detection.languages),
        "frameworks": sorted(detection.frameworks),
        "package_manager": sorted(detection.package_managers),
        "docker": detection.docker,
        "iac": detection.iac,
        "kubernetes": detection.kubernetes,
        "openapi": detection.openapi,
        "frontend": detection.frontend,
        "backend": detection.backend,
        "cloud": cloud_info["cloud"],
        "deployment_target": cloud_info["deployment_target"],
        "deployed_url": cloud_info["deployed_url"],
        "authenticated_testing_available": False,

        # Framework extensions
        "docker_compose_in_repo": detection.docker_compose,
        "dockerfiles": detection.dockerfiles,
        "iac_types": sorted(detection.iac_types),
        "helm": detection.helm,
        "openapi_spec_files": detection.openapi_spec_files,
        "sonar_properties_files": detection.sonar_properties,
        "web_server_config_files": detection.web_server_config_files,
        "ci_workflows": sorted(detection.ci_workflows),
        "source_file_counts": dict(sorted(detection.extension_counts.items(), key=lambda kv: -kv[1])),
        "evidence": detection.evidence,
        "cloud_evidence": cloud_info["cloud_evidence"],
        "deployment_target_evidence": cloud_info["deployment_target_evidence"],
        "authenticated_testing_source": "NOT_ESTABLISHED",
        "overridden_fields": [],
    }

    for key, value in overrides.items():
        if key in capabilities:
            capabilities[key] = value
            capabilities["overridden_fields"].append(key)

    if capabilities["authenticated_testing_available"]:
        capabilities["authenticated_testing_source"] = "explicit input"

    return capabilities
