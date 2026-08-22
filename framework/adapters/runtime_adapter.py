"""Runtime probes -> common Finding schema.

Turns observed runtime configuration into findings covering TLS, security
headers, cookie flags, CORS, version disclosure, exposed debug surfaces, error
disclosure and secrets served in live JavaScript bundles.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..collectors.base import ScannerResult
from ..core.context import RunContext
from ..core.schema import Finding, normalise_severity
from .base import Adapter

TOOL = "runtime-probes"
CATEGORY_KEY = "runtime_probes"

REQUIRED_HEADERS = (
    ("strict-transport-security", "Strict-Transport-Security", "MEDIUM", "CWE-319",
     "Add Strict-Transport-Security with max-age of at least 31536000 (one year)."),
    ("content-security-policy", "Content-Security-Policy", "MEDIUM", "CWE-1021",
     "Define a Content-Security-Policy; it is the primary defence-in-depth control against XSS."),
    ("x-content-type-options", "X-Content-Type-Options", "LOW", "CWE-430",
     "Set X-Content-Type-Options: nosniff."),
    ("x-frame-options", "X-Frame-Options", "LOW", "CWE-1021",
     "Set X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors directive."),
    ("referrer-policy", "Referrer-Policy", "LOW", "CWE-200",
     "Set Referrer-Policy to no-referrer-when-downgrade or stricter."),
    ("permissions-policy", "Permissions-Policy", "INFO", "CWE-1021",
     "Set Permissions-Policy to disable unused browser features."),
)

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

_VERSION_VALUE = re.compile(r"\d+\.\d+")


class RuntimeAdapter(Adapter):
    tool = TOOL
    category_key = CATEGORY_KEY

    def normalize(self, result: ScannerResult, context: RunContext) -> List[Finding]:  # noqa: C901
        payload = result.payload
        if not payload:
            if result.status not in ("FAILED", "SKIPPED"):
                result.fail("Runtime probe payload was empty; findings could not be normalised.")
            return []

        target = payload.get("target", "")
        headers: Dict[str, str] = (payload.get("headers") or {}).get("received") or {}
        findings: List[Finding] = []

        def add(**kwargs: Any) -> None:
            kwargs.setdefault("tool", TOOL)
            kwargs.setdefault("endpoint", target)
            kwargs.setdefault("phase", 5)
            kwargs.setdefault("scanner_category", CATEGORY_KEY)
            findings.append(self.stamp(Finding(**kwargs), context))

        # --- TLS ------------------------------------------------------------
        tls = payload.get("tls") or {}
        if tls.get("scheme") == "http":
            add(
                category="tls", severity="HIGH", cwe="CWE-319", owasp="A2:2021",
                description="Application is served over plain HTTP",
                evidence="%s | scheme=http" % target,
                impact="All traffic, including credentials and session tokens, travels unencrypted "
                       "and can be read or modified in transit.",
                remediation="Serve the application over HTTPS and redirect all HTTP traffic to it.",
                rule="tls_absent",
            )
        if tls.get("verification_error"):
            add(
                category="tls", severity="HIGH", cwe="CWE-295", owasp="A2:2021",
                description="TLS certificate failed verification",
                evidence="%s | %s" % (target, tls["verification_error"]),
                impact="Clients cannot establish trust in the server identity; browsers will warn "
                       "and users may be trained to bypass warnings.",
                remediation="Install a certificate valid for this hostname from a trusted CA, "
                            "including any required intermediate chain.",
                rule="tls_verification_failed",
            )
        days = tls.get("days_until_expiry")
        if isinstance(days, int) and days <= 30:
            add(
                category="tls", severity="HIGH" if days <= 7 else "MEDIUM", cwe="CWE-324",
                owasp="A2:2021",
                description="TLS certificate expires in %d day(s)" % days,
                evidence="%s | notAfter=%s" % (target, tls.get("notAfter", "")),
                impact="An expired certificate causes browser errors and an effective outage.",
                remediation="Renew the certificate and verify automated renewal is working.",
                rule="tls_expiring",
            )
        if tls.get("http_reachable") and not str(tls.get("http_location", "")).lower().startswith("https"):
            add(
                category="tls", severity="MEDIUM", cwe="CWE-319", owasp="A2:2021",
                description="HTTP does not redirect to HTTPS",
                evidence="%s | http_status=%s location=%s"
                         % (target, tls.get("http_status"), tls.get("http_location") or "<none>"),
                impact="Clients arriving over HTTP stay unencrypted, exposing session material.",
                remediation="Return a 301 redirect from HTTP to HTTPS for all paths.",
                rule="no_https_redirect",
            )

        # --- Security headers ------------------------------------------------
        for key, label, severity, cwe, remediation in REQUIRED_HEADERS:
            if key not in headers:
                add(
                    category="security_header", severity=severity, cwe=cwe, owasp="A5:2021",
                    description="Missing security header: %s" % label,
                    evidence="%s | header %s absent" % (target, label),
                    impact="Defence-in-depth control absent. The application relies entirely on "
                           "application-level correctness for this class of attack.",
                    remediation=remediation, rule="missing_header_%s" % key,
                )
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if match and int(match.group(1)) < 31536000:
                add(
                    category="security_header", severity="LOW", cwe="CWE-319", owasp="A5:2021",
                    description="HSTS max-age is shorter than one year",
                    evidence="%s | max-age=%s" % (target, match.group(1)),
                    impact="A short HSTS window narrows protection against downgrade attacks.",
                    remediation="Set max-age to at least 31536000.",
                    rule="weak_hsts_max_age",
                )

        # --- Version disclosure ----------------------------------------------
        for key in VERSION_HEADERS:
            value = headers.get(key)
            if value and _VERSION_VALUE.search(value):
                add(
                    category="information_disclosure", severity="LOW", cwe="CWE-200", owasp="A5:2021",
                    description="Server version disclosed in %s header" % key,
                    evidence="%s | %s: %s" % (target, key, value),
                    impact="Precise version information lets an attacker match known CVEs to this "
                           "deployment without probing.",
                    remediation="Suppress version detail (for example nginx `server_tokens off`, "
                                "or remove X-Powered-By).",
                    rule="version_disclosure_%s" % key,
                )

        # --- Cookies ----------------------------------------------------------
        for cookie in payload.get("cookies") or []:
            missing = []
            if not cookie.get("secure"):
                missing.append("Secure")
            if not cookie.get("httponly"):
                missing.append("HttpOnly")
            if not cookie.get("samesite"):
                missing.append("SameSite")
            if missing:
                add(
                    category="cookie_security",
                    severity="MEDIUM" if "HttpOnly" in missing or "Secure" in missing else "LOW",
                    cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614", owasp="A5:2021",
                    description="Cookie %s missing flag(s): %s" % (cookie.get("name"), ", ".join(missing)),
                    evidence="%s | cookie=%s missing=%s" % (target, cookie.get("name"), ",".join(missing)),
                    impact="Missing HttpOnly exposes the cookie to script; missing Secure allows "
                           "transmission over plaintext; missing SameSite enables cross-site sending.",
                    remediation="Set Secure, HttpOnly and SameSite on all session cookies.",
                    rule="cookie_flags",
                )

        # --- CORS -------------------------------------------------------------
        cors = payload.get("cors") or {}
        allow_origin = cors.get("allow_origin", "")
        credentials = str(cors.get("allow_credentials", "")).lower() == "true"
        if allow_origin == "*":
            add(
                category="cors", severity="MEDIUM" if not credentials else "HIGH",
                cwe="CWE-942", owasp="A5:2021",
                description="CORS allows any origin (*)%s" % (" with credentials" if credentials else ""),
                evidence="%s | Access-Control-Allow-Origin: * credentials=%s" % (target, credentials),
                impact="Any website can read responses from this API on behalf of a visitor."
                       + (" With credentials enabled this extends to authenticated responses." if credentials else ""),
                remediation="Replace the wildcard with an explicit allowlist of production origins.",
                rule="cors_wildcard",
            )
        elif cors.get("reflects_arbitrary_origin"):
            add(
                category="cors", severity="HIGH" if credentials else "MEDIUM",
                cwe="CWE-942", owasp="A5:2021",
                description="CORS reflects arbitrary request origins",
                evidence="%s | reflected origin=%s credentials=%s"
                         % (target, cors.get("probe_origin"), credentials),
                impact="Origin reflection is equivalent to a wildcard but bypasses the browser's "
                       "wildcard-plus-credentials restriction, so it is often more dangerous.",
                remediation="Validate the Origin header against a fixed allowlist; never echo it back.",
                rule="cors_origin_reflection",
            )

        # --- Debug surfaces ---------------------------------------------------
        for surface in payload.get("debug_surfaces") or []:
            severity = surface.get("severity", "MEDIUM")
            if severity == "INFO":
                continue
            add(
                category="exposed_surface", severity=normalise_severity(severity),
                raw_severity=str(severity), cwe="CWE-200", owasp="A5:2021",
                description="%s is publicly accessible at %s" % (surface.get("label"), surface.get("path")),
                endpoint=target + str(surface.get("path")),
                evidence="%s%s | status=%s bytes=%s"
                         % (target, surface.get("path"), surface.get("status"), surface.get("bytes")),
                impact="Debug and metadata surfaces disclose internal structure, configuration or "
                       "the full API surface to unauthenticated users.",
                remediation="Disable the endpoint in production, or place it behind authentication "
                            "and network restriction.",
                rule="exposed_%s" % str(surface.get("path")).strip("/").replace("/", "_"),
            )

        # --- Error disclosure --------------------------------------------------
        for page in payload.get("error_pages") or []:
            if page.get("stack_trace_detected"):
                add(
                    category="information_disclosure", severity="MEDIUM", cwe="CWE-209", owasp="A5:2021",
                    description="Error response contains a stack trace",
                    endpoint=target + str(page.get("path")),
                    evidence="%s%s | status=%s stack_trace=true" % (target, page.get("path"), page.get("status")),
                    impact="Stack traces disclose framework versions, file paths and internal "
                           "structure, and often the shape of the data layer.",
                    remediation="Return generic error pages in production and log detail server-side.",
                    rule="stack_trace_in_response",
                )

        # --- Live JavaScript bundle validation ---------------------------------
        from .bundle_adapter import BundleAdapter

        bundles = payload.get("bundles") or {}
        if bundles.get("matches"):
            proxy = ScannerResult(tool=TOOL, category_key=CATEGORY_KEY)
            proxy.payload = {"matches": bundles["matches"], "sourcemaps": []}
            proxy.succeed()
            findings.extend(BundleAdapter().normalize(proxy, context))

        return findings
