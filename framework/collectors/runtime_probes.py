"""Runtime security probes — framework-native, no external tool.

Post-deployment checks against a running application:

  * TLS posture: HTTPS reachable, HTTP->HTTPS redirect, certificate validity
  * Security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy, Permissions-Policy
  * Cookie flags: Secure, HttpOnly, SameSite
  * CORS: wildcard origin, origin reflection, credentialed wildcard
  * Server/framework version disclosure
  * Exposed debug and metadata surfaces (Swagger, actuator, .env, .git, ...)
  * Stack traces and internal detail in error responses
  * Live JavaScript bundle validation: fetches the scripts the page actually
    loads and scans them for secrets

SAFETY CONTRACT
---------------
Every probe is a plain GET/HEAD of a URL. This module sends no injection
payloads, performs no fuzzing, no brute force, no write method (POST/PUT/DELETE),
and no authentication attempt. It is a configuration observer, not an attack
tool. It requires an explicit target and never guesses one.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..core.registry import ScannerRegistration, register_scanner
from ..core.secretpatterns import scan_text
from .base import Collector, ScannerResult

TOOL = "runtime-probes"
CATEGORY_KEY = "runtime_probes"

DEFAULT_TIMEOUT = 20
USER_AGENT = "devsecops-framework/runtime-probes (read-only configuration check)"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_BUNDLES = 25

# Read-only paths that commonly expose debug or metadata surfaces.
DEBUG_PATHS = (
    ("/swagger/index.html", "Swagger UI", "HIGH"),
    ("/swagger/v1/swagger.json", "OpenAPI specification", "HIGH"),
    ("/swagger-ui.html", "Swagger UI", "HIGH"),
    ("/api-docs", "API documentation", "MEDIUM"),
    ("/actuator/health", "Spring Boot actuator", "MEDIUM"),
    ("/actuator/env", "Spring Boot environment endpoint", "CRITICAL"),
    ("/.env", "Environment file", "CRITICAL"),
    ("/.git/config", "Git metadata", "CRITICAL"),
    ("/phpinfo.php", "PHP configuration dump", "HIGH"),
    ("/server-status", "Apache server status", "MEDIUM"),
    ("/debug/pprof/", "Go pprof profiling endpoint", "HIGH"),
    ("/.well-known/security.txt", "security.txt (informational)", "INFO"),
)

REQUIRED_HEADERS = (
    ("strict-transport-security", "HSTS", "MEDIUM",
     "Add Strict-Transport-Security with a max-age of at least 31536000."),
    ("content-security-policy", "Content-Security-Policy", "MEDIUM",
     "Define a Content-Security-Policy; it is the primary defence-in-depth control against XSS."),
    ("x-content-type-options", "X-Content-Type-Options", "LOW",
     "Set X-Content-Type-Options: nosniff."),
    ("x-frame-options", "X-Frame-Options", "LOW",
     "Set X-Frame-Options: DENY or SAMEORIGIN, or an equivalent CSP frame-ancestors directive."),
    ("referrer-policy", "Referrer-Policy", "LOW",
     "Set Referrer-Policy to no-referrer-when-downgrade or stricter."),
    ("permissions-policy", "Permissions-Policy", "INFO",
     "Set Permissions-Policy to disable browser features the application does not use."),
)

VERSION_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

_STACK_TRACE = re.compile(
    r"(?:at\s+[\w$.]+\s*\([^)]*:\d+:\d+\)|Traceback \(most recent call last\)|"
    r"System\.[A-Za-z.]+Exception|java\.lang\.[A-Za-z]+Exception|"
    r"Fatal error:|Warning:\s+\w+\(\)|\bstack trace\b)",
    re.IGNORECASE,
)
_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


class _Response:
    def __init__(self, status: int, headers: Dict[str, str], body: str, url: str, error: str = "") -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body
        self.url = url
        self.error = error

    @property
    def ok(self) -> bool:
        return not self.error and 0 < self.status < 600


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, N802
        return None


def _fetch(url: str, timeout: int = DEFAULT_TIMEOUT, follow: bool = True,
           extra_headers: Optional[Dict[str, str]] = None, max_bytes: int = 1_000_000) -> _Response:
    """Read-only GET. Never raises."""
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", "*/*")
    for key, value in (extra_headers or {}).items():
        request.add_header(key, value)

    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes).decode("utf-8", errors="replace")
            return _Response(response.status, dict(response.headers), body, response.url)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        return _Response(exc.code, dict(exc.headers or {}), body, url)
    except urllib.error.URLError as exc:
        return _Response(0, {}, "", url, error=str(exc.reason))
    except (TimeoutError, ssl.SSLError, socket.error) as exc:
        return _Response(0, {}, "", url, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        return _Response(0, {}, "", url, error=str(exc))


def _tls_certificate(host: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Retrieve certificate metadata. Read-only handshake."""
    info: Dict[str, Any] = {"reachable": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                info["reachable"] = True
                info["protocol"] = tls.version()
                info["cipher"] = tls.cipher()[0] if tls.cipher() else ""
                info["subject"] = dict(x[0] for x in cert.get("subject", ()) if x)
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()) if x)
                info["notAfter"] = cert.get("notAfter", "")
                info["subjectAltName"] = [v for (_k, v) in cert.get("subjectAltName", ())]
                if info["notAfter"]:
                    expires = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    info["days_until_expiry"] = (expires - datetime.now(timezone.utc)).days
    except ssl.SSLCertVerificationError as exc:
        info["verification_error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        info["error"] = str(exc)
    return info


class RuntimeProbeCollector(Collector):
    tool = TOOL
    category_key = CATEGORY_KEY
    ACCEPTS = {"target_url", "timeout", "validate_bundles"}

    def __init__(
        self,
        target_url: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        validate_bundles: bool = True,
    ) -> None:
        self.target_url = (target_url or "").strip().rstrip("/")
        self.timeout = timeout
        self.validate_bundles = validate_bundles

    def collect(self) -> ScannerResult:  # noqa: C901 - linear probe sequence
        result = self.new_result()
        result.metadata["read_only"] = True
        result.metadata["methods_used"] = ["GET"]

        if not self.target_url:
            return result.skip(
                "No deployed URL was supplied (input 'deployed_url'). Runtime security was NOT "
                "tested, so this category is unverified. Runtime testing cannot be inferred from "
                "a successful deployment."
            ).finish()

        parsed = urllib.parse.urlsplit(self.target_url if "://" in self.target_url else "https://" + self.target_url)
        if parsed.scheme not in ("http", "https"):
            return result.fail("Target URL scheme %r is not supported." % parsed.scheme).finish()

        host = parsed.hostname or ""
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        result.metadata["target"] = base

        payload: Dict[str, Any] = {
            "_tool": TOOL,
            "_read_only": True,
            "target": base,
            "tls": {},
            "headers": {},
            "cookies": [],
            "cors": {},
            "debug_surfaces": [],
            "error_pages": [],
            "bundles": {"scanned": [], "matches": []},
            "probe_errors": [],
        }

        # --- 1. Base page ----------------------------------------------------
        root = _fetch(base + "/", timeout=self.timeout)
        if not root.ok:
            return result.fail(
                "Target %s could not be reached: %s. Runtime security is unverified."
                % (base, root.error or "no response")
            ).finish()

        payload["headers"] = {"status": root.status, "received": dict(root.headers)}

        # --- 2. TLS ----------------------------------------------------------
        if parsed.scheme == "https" and host:
            payload["tls"] = _tls_certificate(host, parsed.port or 443, self.timeout)
        else:
            payload["tls"] = {"scheme": "http", "reachable": False}

        # HTTP -> HTTPS redirect behaviour.
        if host:
            http_probe = _fetch("http://%s/" % host, timeout=self.timeout, follow=False)
            payload["tls"]["http_status"] = http_probe.status
            payload["tls"]["http_location"] = http_probe.headers.get("location", "")
            payload["tls"]["http_reachable"] = http_probe.ok

        # --- 3. Cookies ------------------------------------------------------
        raw_cookies = root.headers.get("set-cookie", "")
        if raw_cookies:
            for cookie in re.split(r",(?=[^;]+=)", raw_cookies):
                name = cookie.split("=", 1)[0].strip()
                lowered = cookie.lower()
                payload["cookies"].append(
                    {
                        "name": name,
                        "secure": "secure" in lowered,
                        "httponly": "httponly" in lowered,
                        "samesite": (
                            re.search(r"samesite=(\w+)", lowered).group(1)
                            if re.search(r"samesite=(\w+)", lowered) else ""
                        ),
                    }
                )

        # --- 4. CORS ---------------------------------------------------------
        probe_origin = "https://devsecops-framework-probe.invalid"
        cors = _fetch(base + "/", timeout=self.timeout, extra_headers={"Origin": probe_origin})
        payload["cors"] = {
            "probe_origin": probe_origin,
            "allow_origin": cors.headers.get("access-control-allow-origin", ""),
            "allow_credentials": cors.headers.get("access-control-allow-credentials", ""),
            "reflects_arbitrary_origin": cors.headers.get("access-control-allow-origin", "") == probe_origin,
        }

        # --- 5. Debug surfaces ----------------------------------------------
        for path, label, severity in DEBUG_PATHS:
            probe = _fetch(base + path, timeout=self.timeout, max_bytes=4096)
            if probe.ok and 200 <= probe.status < 300 and probe.body.strip():
                payload["debug_surfaces"].append(
                    {"path": path, "label": label, "severity": severity,
                     "status": probe.status, "bytes": len(probe.body)}
                )
            elif probe.error:
                payload["probe_errors"].append({"path": path, "error": probe.error})

        # --- 6. Error page disclosure ---------------------------------------
        marker = "/devsecops-framework-nonexistent-path-probe"
        err = _fetch(base + marker, timeout=self.timeout, max_bytes=200_000)
        if err.ok:
            payload["error_pages"].append(
                {
                    "path": marker,
                    "status": err.status,
                    "stack_trace_detected": bool(_STACK_TRACE.search(err.body)),
                    "bytes": len(err.body),
                }
            )

        # --- 7. Live JavaScript bundle validation ---------------------------
        if self.validate_bundles:
            scripts = _SCRIPT_SRC.findall(root.body or "")
            urls: List[str] = []
            for src in scripts:
                if src.startswith("//"):
                    url = parsed.scheme + ":" + src
                elif src.startswith("http://") or src.startswith("https://"):
                    url = src
                else:
                    url = urllib.parse.urljoin(base + "/", src)
                # Only validate assets served by the target itself.
                if urllib.parse.urlsplit(url).hostname == host and url not in urls:
                    urls.append(url)

            for url in urls[:MAX_BUNDLES]:
                asset = _fetch(url, timeout=self.timeout, max_bytes=MAX_BUNDLE_BYTES)
                if not asset.ok or not asset.body:
                    payload["probe_errors"].append({"path": url, "error": asset.error or "empty"})
                    continue
                label = urllib.parse.urlsplit(url).path or url
                payload["bundles"]["scanned"].append({"url": label, "bytes": len(asset.body)})
                for match in scan_text(asset.body, label):
                    payload["bundles"]["matches"].append(
                        {
                            "detector": match.detector, "severity": match.severity,
                            "cwe": match.cwe, "description": match.description,
                            "remediation": match.remediation, "file": match.file,
                            "line": match.line, "reference": match.reference,
                            "entropy": match.entropy,
                        }
                    )
            if len(urls) > MAX_BUNDLES:
                result.partial(
                    "Only the first %d of %d scripts were validated; bundle coverage is incomplete."
                    % (MAX_BUNDLES, len(urls))
                )
            if not urls:
                result.partial(
                    "No same-origin script tags were found on the landing page; live bundle "
                    "validation covered nothing."
                )

        if payload["probe_errors"]:
            result.partial("%d probe(s) could not be completed." % len(payload["probe_errors"]))

        result.payload = payload
        result.metadata["debug_surfaces"] = len(payload["debug_surfaces"])
        result.metadata["bundles_scanned"] = len(payload["bundles"]["scanned"])
        return result.succeed().finish()


def _build_collector(**kwargs: Any) -> RuntimeProbeCollector:
    mapped = dict(kwargs)
    if "deployed_url" in mapped and "target_url" not in mapped:
        mapped["target_url"] = mapped["deployed_url"]
    return RuntimeProbeCollector(**{k: v for k, v in mapped.items() if k in RuntimeProbeCollector.ACCEPTS})


def _build_adapter(**_: Any) -> Any:
    from ..adapters.runtime_adapter import RuntimeAdapter

    return RuntimeAdapter()


register_scanner(
    ScannerRegistration(
        tool=TOOL,
        category_key=CATEGORY_KEY,
        collector_factory=_build_collector,
        adapter_factory=_build_adapter,
        description="Framework-native runtime probes: TLS, headers, cookies, CORS, debug surfaces, live bundles.",
    )
)
