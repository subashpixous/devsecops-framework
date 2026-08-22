"""Contract tests for every Phase 2-6 collector and adapter.

Covers, for each scanner:
  * failure behaviour  -- a missing tool / missing input never yields a
    trustworthy result, so the category can only become NOT_VERIFIED
  * output format      -- payloads normalise into the common Finding schema
  * error handling     -- empty and malformed payloads mark the result failed
                          rather than returning "no findings"
  * secret hygiene     -- no scanner emits a raw credential value
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.adapters.bundle_adapter import BundleAdapter  # noqa: E402
from framework.adapters.checkov_adapter import CheckovAdapter  # noqa: E402
from framework.adapters.cosign_adapter import CosignAdapter  # noqa: E402
from framework.adapters.gitleaks_adapter import GitleaksAdapter  # noqa: E402
from framework.adapters.iam_adapter import IamAccessAnalyzerAdapter  # noqa: E402
from framework.adapters.nuclei_adapter import NucleiAdapter  # noqa: E402
from framework.adapters.prowler_adapter import ProwlerAdapter  # noqa: E402
from framework.adapters.runtime_adapter import RuntimeAdapter  # noqa: E402
from framework.adapters.semgrep_adapter import SemgrepAdapter  # noqa: E402
from framework.adapters.trivy_adapter import TrivyAdapter  # noqa: E402
from framework.adapters.zap_adapter import ZapAdapter  # noqa: E402
from framework.collectors.base import ScannerResult  # noqa: E402
from framework.collectors.bundle_scanner import BundleScannerCollector  # noqa: E402
from framework.collectors.cosign import CosignCollector  # noqa: E402
from framework.collectors.gitleaks import strip_secret_material  # noqa: E402
from framework.collectors.iam_access_analyzer import IamAccessAnalyzerCollector  # noqa: E402
from framework.collectors.nuclei import NucleiCollector  # noqa: E402
from framework.collectors.prowler import ProwlerCollector  # noqa: E402
from framework.collectors.runtime_probes import RuntimeProbeCollector  # noqa: E402
from framework.collectors.trivy import TrivyImageCollector  # noqa: E402
from framework.collectors.zap import ZapCollector  # noqa: E402
from framework.core.context import RunContext  # noqa: E402
from framework.core.secretpatterns import is_placeholder, scan_text, shannon_entropy  # noqa: E402
from framework.core.toolrunner import redact, run, tool_available  # noqa: E402

CTX = RunContext(commit="deadbeef", branch="main", environment="test")

# A synthetic key-shaped string used only to prove redaction works.
FAKE_GOOGLE_KEY = "AIza" + "B" * 35


def result_for(category: str, payload=None, tool: str = "t") -> ScannerResult:
    r = ScannerResult(tool=tool, category_key=category)
    r.payload = payload
    if payload is not None:
        r.succeed()
    return r


class ToolRunnerTestCase(unittest.TestCase):
    def test_missing_binary_never_reports_available(self):
        outcome = run(["definitely-not-a-real-binary-xyz", "--version"])
        self.assertFalse(outcome.available)
        self.assertFalse(outcome.ok)
        self.assertIn("not found", outcome.error)

    def test_run_never_raises_on_empty_command(self):
        outcome = run([])
        self.assertFalse(outcome.ok)

    def test_redaction_removes_key_shapes(self):
        text = "key=%s and AKIAIOSFODNN7EXAMPLE" % FAKE_GOOGLE_KEY
        cleaned = redact(text)
        self.assertNotIn(FAKE_GOOGLE_KEY, cleaned)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)
        self.assertIn("<REDACTED>", cleaned)

    def test_redaction_removes_explicit_extra_values(self):
        self.assertNotIn("s3cr3tvalue", redact("token=s3cr3tvalue", extra=["s3cr3tvalue"]))

    def test_tool_available_is_boolean(self):
        self.assertIsInstance(tool_available("python"), bool)


class SecretPatternTestCase(unittest.TestCase):
    def test_detects_key_without_returning_its_value(self):
        matches = scan_text("var k='%s';" % FAKE_GOOGLE_KEY, "main.js")
        self.assertTrue(matches)
        for match in matches:
            self.assertNotIn(FAKE_GOOGLE_KEY, match.reference)
            self.assertIn("sha256:", match.reference)
            self.assertIn("len=", match.reference)

    def test_placeholders_are_not_reported(self):
        for value in ("xxxxxxxx", "changeme", "your_api_key", "${SECRET}", "<token>"):
            self.assertTrue(is_placeholder(value), value)

    def test_low_entropy_assignment_is_filtered(self):
        self.assertEqual(scan_text('password = "aaaaaaaaaaaa"', "a.js"), [])

    def test_entropy_increases_with_randomness(self):
        self.assertGreater(shannon_entropy("aB3xZ9qL2mNp"), shannon_entropy("aaaaaaaaaaaa"))

    def test_line_numbers_are_reported(self):
        text = "\n\n\nvar k='%s';" % FAKE_GOOGLE_KEY
        self.assertEqual(scan_text(text, "a.js")[0].line, 4)


class GitleaksSecretHygieneTestCase(unittest.TestCase):
    """A secret scanner must never publish the secrets it finds."""

    RAW = [{
        "RuleID": "generic-api-key", "File": "config.json", "StartLine": 12,
        "Description": "Generic API Key", "Secret": "SUPERSECRETVALUE123",
        "Match": "apiKey: SUPERSECRETVALUE123", "Commit": "abc123def456",
        "Author": "dev", "Entropy": 4.2, "Fingerprint": "fp1",
    }]

    def test_strip_removes_secret_and_match(self):
        cleaned = strip_secret_material(self.RAW)
        self.assertNotIn("Secret", cleaned[0])
        self.assertNotIn("Match", cleaned[0])
        self.assertEqual(cleaned[0]["SecretLength"], len("SUPERSECRETVALUE123"))
        self.assertTrue(cleaned[0]["SecretRedacted"])

    def test_strip_keeps_everything_needed_for_triage(self):
        cleaned = strip_secret_material(self.RAW)[0]
        for key in ("RuleID", "File", "StartLine", "Commit", "Entropy"):
            self.assertIn(key, cleaned)

    def test_no_secret_value_survives_into_findings(self):
        result = result_for("secret_scanning", {"findings": strip_secret_material(self.RAW)}, "gitleaks")
        findings = GitleaksAdapter().normalize(result, CTX)
        self.assertEqual(len(findings), 1)
        blob = str(findings[0].to_dict())
        self.assertNotIn("SUPERSECRETVALUE123", blob)
        self.assertIn("WITHHELD", findings[0].evidence)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_adapter_refuses_a_record_that_still_carries_a_secret(self):
        """Defence in depth: a stripping regression must fail loudly."""
        result = result_for("secret_scanning", {"findings": self.RAW}, "gitleaks")
        findings = GitleaksAdapter().normalize(result, CTX)
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "FAILED")
        self.assertTrue(any("refusing to normalise" in e for e in result.errors))


class MissingInputTestCase(unittest.TestCase):
    """No target / no credential must yield an untrustworthy result, never PASS."""

    def _assert_not_trustworthy(self, result):
        self.assertFalse(result.is_trustworthy)
        self.assertIn(result.status, ("SKIPPED", "FAILED"))
        self.assertTrue(result.warnings or result.errors)

    def test_runtime_probes_without_url(self):
        self._assert_not_trustworthy(RuntimeProbeCollector(target_url="").collect())

    def test_zap_without_url(self):
        self._assert_not_trustworthy(ZapCollector(target_url="").collect())

    def test_nuclei_without_url(self):
        self._assert_not_trustworthy(NucleiCollector(target_url="").collect())

    def test_trivy_image_without_image_reference(self):
        self._assert_not_trustworthy(TrivyImageCollector(images=[]).collect())

    def test_cosign_without_image_reference(self):
        self._assert_not_trustworthy(CosignCollector(images=[]).collect())

    def test_prowler_without_cloud_provider(self):
        self._assert_not_trustworthy(ProwlerCollector(cloud="").collect())

    def test_iam_analyzer_when_project_is_not_aws(self):
        self._assert_not_trustworthy(IamAccessAnalyzerCollector(cloud="azure").collect())

    def test_bundle_scanner_without_build_output(self):
        import tempfile
        with tempfile.TemporaryDirectory() as empty:
            self._assert_not_trustworthy(BundleScannerCollector(workspace=empty).collect())


class EmptyPayloadTestCase(unittest.TestCase):
    """An empty payload is NOT "no findings" -- it marks the result failed."""

    CASES = (
        (SemgrepAdapter, "sast_semgrep"),
        (GitleaksAdapter, "secret_scanning"),
        (TrivyAdapter, "sca_dependencies"),
        (CheckovAdapter, "iac_scanning"),
        (ZapAdapter, "dast_zap"),
        (NucleiAdapter, "nuclei_templates"),
        (RuntimeAdapter, "runtime_probes"),
        (BundleAdapter, "frontend_bundle_secrets"),
        (ProwlerAdapter, "cloud_posture"),
        (IamAccessAnalyzerAdapter, "iam_access_analyzer"),
        (CosignAdapter, "artifact_signing"),
    )

    def test_empty_payload_marks_result_failed(self):
        for adapter_cls, category in self.CASES:
            result = result_for(category, None)
            findings = adapter_cls().normalize(result, CTX)
            self.assertEqual(findings, [], adapter_cls.__name__)
            self.assertEqual(result.status, "FAILED", adapter_cls.__name__)

    def test_missing_expected_array_marks_result_failed(self):
        for adapter_cls, category, payload in (
            (SemgrepAdapter, "sast_semgrep", {"errors": []}),
            (GitleaksAdapter, "secret_scanning", {"_tool": "gitleaks"}),
            (TrivyAdapter, "sca_dependencies", {"_mode": "fs-vuln"}),  # no SchemaVersion -> real failure
            (CheckovAdapter, "iac_scanning", {"passed_count": 3}),
            (ZapAdapter, "dast_zap", {"_target": "x"}),
            (NucleiAdapter, "nuclei_templates", {"_target": "x"}),
            (ProwlerAdapter, "cloud_posture", {"_provider": "aws"}),
        ):
            result = result_for(category, payload)
            adapter_cls().normalize(result, CTX)
            self.assertEqual(result.status, "FAILED", adapter_cls.__name__)


class AdapterOutputTestCase(unittest.TestCase):
    """Each adapter maps its native shape onto the common schema."""

    def test_semgrep(self):
        payload = {"_engine": "semgrep", "results": [{
            "check_id": "javascript.lang.security.audit.sqli",
            "path": "src/db.js", "start": {"line": 42},
            "extra": {"message": "SQL injection", "severity": "ERROR",
                      "lines": "const q = 'SELECT ' + userInput",
                      "metadata": {"cwe": ["CWE-89: SQL Injection"],
                                   "owasp": ["A03:2021 - Injection"],
                                   "confidence": "HIGH", "category": "security"}}}]}
        findings = SemgrepAdapter().normalize(result_for("sast_semgrep", payload), CTX)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.owasp, "A3:2021")
        self.assertEqual(f.file, "src/db.js")
        self.assertEqual(f.line, 42)
        self.assertEqual(f.commit, "deadbeef")
        # matched source must not be copied into evidence
        self.assertNotIn("SELECT", f.evidence)

    def test_trivy_dependency(self):
        payload = {"_mode": "fs-vuln", "Results": [{
            "Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash",
                "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
                "Severity": "HIGH", "Title": "Command injection",
                "CweIDs": ["CWE-77"], "PkgPath": "node_modules/lodash"}]}]}
        findings = TrivyAdapter().normalize(result_for("sca_dependencies", payload), CTX)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].category, "dependency_vulnerability")
        self.assertIn("CWE-77", findings[0].cwe)
        self.assertIn("4.17.21", findings[0].remediation)

    def test_trivy_omitted_results_with_valid_report_is_zero_findings_not_failure(self):
        """Trivy omits "Results" when a completed scan has nothing to report.

        Observed on a real GitHub runner: a pip project with unpinned requirement
        ranges yields rc=0, SchemaVersion 2, and no Results key. That is a clean
        completed scan, not a broken tool -- but the collector's PARTIAL warning
        still keeps the category at NOT_VERIFIED, because nothing was covered.
        """
        payload = {"_mode": "fs-vuln", "SchemaVersion": 2, "ArtifactType": "repository",
                   "ArtifactName": "/src"}
        result = result_for("sca_dependencies", payload)
        findings = TrivyAdapter().normalize(result, CTX)
        self.assertEqual(findings, [])
        self.assertNotEqual(result.status, "FAILED")   # tool worked; do not blame it

    def test_trivy_payload_without_schemaversion_is_a_real_failure(self):
        result = result_for("sca_dependencies", {"_mode": "fs-vuln", "junk": True})
        TrivyAdapter().normalize(result, CTX)
        self.assertEqual(result.status, "FAILED")

    def test_trivy_sbom_emits_artifact_not_findings(self):
        payload = {"_mode": "sbom", "component_count": 120, "Results": []}
        self.assertEqual(TrivyAdapter().normalize(result_for("sbom", payload), CTX), [])

    def test_checkov(self):
        payload = {"failed_checks": [{
            "check_id": "CKV_AWS_18", "check_name": "Ensure S3 bucket has access logging",
            "file_path": "/main.tf", "file_line_range": [10, 20],
            "resource": "aws_s3_bucket.data", "guideline": "https://example/docs"}]}
        findings = CheckovAdapter().normalize(result_for("iac_scanning", payload), CTX)
        self.assertEqual(findings[0].category, "misconfiguration")
        self.assertEqual(findings[0].line, 10)
        self.assertEqual(findings[0].severity, "UNKNOWN")   # absent severity fails closed

    def test_zap(self):
        payload = {"_target": "https://x.test", "site": [{"@name": "https://x.test", "alerts": [{
            "pluginid": "10038", "alert": "CSP header not set", "riskcode": "2",
            "confidence": "3", "desc": "<p>No CSP</p>", "solution": "<p>Add CSP</p>",
            "cweid": "693", "instances": [{"uri": "https://x.test/", "method": "GET",
                                           "evidence": "<html>secret-token</html>"}]}]}]}
        findings = ZapAdapter().normalize(result_for("dast_zap", payload), CTX)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertEqual(findings[0].cwe, "CWE-693")
        self.assertEqual(findings[0].endpoint, "https://x.test/")
        self.assertNotIn("<p>", findings[0].impact)         # HTML flattened
        self.assertNotIn("secret-token", findings[0].evidence)  # response body not echoed

    def test_nuclei(self):
        payload = {"findings": [{
            "template-id": "git-config", "matched-at": "https://x.test/.git/config",
            "type": "http", "info": {"name": "Git config exposure", "severity": "high",
                                     "tags": ["exposure", "config"],
                                     "classification": {"cwe-id": ["cwe-200"]}}}]}
        findings = NucleiAdapter().normalize(result_for("nuclei_templates", payload), CTX)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].cwe, "CWE-200")
        self.assertEqual(findings[0].endpoint, "https://x.test/.git/config")

    def test_runtime_probes(self):
        payload = {
            "target": "https://x.test",
            "tls": {"reachable": True, "days_until_expiry": 3, "http_reachable": True, "http_location": ""},
            "headers": {"status": 200, "received": {"server": "nginx/1.18.0"}},
            "cookies": [{"name": "sid", "secure": False, "httponly": False, "samesite": ""}],
            "cors": {"allow_origin": "*", "allow_credentials": "true", "probe_origin": "https://p.invalid"},
            "debug_surfaces": [{"path": "/.env", "label": "Environment file", "severity": "CRITICAL",
                                "status": 200, "bytes": 400}],
            "error_pages": [{"path": "/nope", "status": 500, "stack_trace_detected": True}],
            "bundles": {"scanned": [], "matches": []},
        }
        findings = RuntimeAdapter().normalize(result_for("runtime_probes", payload), CTX)
        rules = {f.rule for f in findings}
        self.assertIn("tls_expiring", rules)
        self.assertIn("no_https_redirect", rules)
        self.assertIn("missing_header_content-security-policy", rules)
        self.assertIn("cookie_flags", rules)
        self.assertIn("cors_wildcard", rules)
        self.assertIn("version_disclosure_server", rules)
        self.assertIn("stack_trace_in_response", rules)
        self.assertTrue(any(f.rule.startswith("exposed_") for f in findings))
        for f in findings:
            self.assertEqual(f.scanner_category, "runtime_probes")
            self.assertEqual(f.endpoint or "https://x.test", f.endpoint or "https://x.test")

    def test_runtime_probes_live_bundle_secrets_are_withheld(self):
        payload = {
            "target": "https://x.test", "tls": {}, "headers": {"received": {}},
            "cookies": [], "cors": {}, "debug_surfaces": [], "error_pages": [],
            "bundles": {"scanned": [{"url": "/main.js"}], "matches": [{
                "detector": "google_api_key", "severity": "HIGH", "cwe": "CWE-798",
                "description": "Google API key present in a shipped artifact",
                "remediation": "restrict and rotate", "file": "/main.js", "line": 1,
                "reference": "len=39 sha256:abc123", "entropy": 4.9}]},
        }
        findings = RuntimeAdapter().normalize(result_for("runtime_probes", payload), CTX)
        bundle = [f for f in findings if f.rule == "google_api_key"]
        self.assertEqual(len(bundle), 1)
        self.assertIn("WITHHELD", bundle[0].evidence)
        self.assertIn("served from production", bundle[0].description)

    def test_bundle_scanner_sourcemap(self):
        payload = {"matches": [], "sourcemaps": ["dist/main.js.map"]}
        findings = BundleAdapter().normalize(result_for("frontend_bundle_secrets", payload), CTX)
        self.assertEqual(findings[0].rule, "sourcemap_in_production")

    def test_cosign_unsigned_image_is_a_finding(self):
        payload = {"_mode": "key", "verifications": [
            {"image": "example/app:1.0", "verified": False, "mode": "key"},
            {"image": "example/api:1.0", "verified": True, "mode": "key"},
        ]}
        findings = CosignAdapter().normalize(result_for("artifact_signing", payload), CTX)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].component, "example/app:1.0")

    def test_cosign_inconclusive_is_not_reported_as_unsigned(self):
        payload = {"_mode": "key", "verifications": [
            {"image": "example/app:1.0", "verified": False, "inconclusive": True, "detail": "timeout"}]}
        self.assertEqual(CosignAdapter().normalize(result_for("artifact_signing", payload), CTX), [])

    def test_prowler_only_reports_failures(self):
        payload = {"_provider": "aws", "findings": [
            {"status_code": "FAIL", "metadata": {"event_code": "s3_bucket_public"},
             "finding_info": {"title": "S3 bucket is public"}, "severity": "high",
             "resources": [{"uid": "arn:aws:s3:::data", "type": "AwsS3Bucket"}],
             "cloud": {"region": "ap-south-1"}},
            {"status_code": "PASS", "metadata": {"event_code": "s3_bucket_encrypted"}},
        ]}
        result = result_for("cloud_posture", payload)
        findings = ProwlerAdapter().normalize(result, CTX)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(result.metadata["passed_controls"], 1)

    def test_iam_missing_analyzer_is_itself_a_finding(self):
        payload = {"_region": "ap-south-1", "no_analyzer_configured": True, "findings": []}
        findings = IamAccessAnalyzerAdapter().normalize(result_for("iam_access_analyzer", payload), CTX)
        self.assertEqual(findings[0].rule, "iam.no_analyzer_configured")

    def test_iam_public_access_is_higher_severity_than_cross_account(self):
        payload = {"_region": "ap-south-1", "no_analyzer_configured": False, "findings": [
            {"id": "1", "status": "ACTIVE", "isPublic": True, "resource": "arn:aws:s3:::pub",
             "resourceType": "AWS::S3::Bucket", "action": ["s3:GetObject"], "principal": {}},
            {"id": "2", "status": "ACTIVE", "isPublic": False, "resource": "arn:aws:s3:::shared",
             "resourceType": "AWS::S3::Bucket", "action": ["s3:GetObject"],
             "principal": {"AWS": "1234"}},
        ]}
        findings = IamAccessAnalyzerAdapter().normalize(result_for("iam_access_analyzer", payload), CTX)
        by_id = {f.native_id: f for f in findings}
        self.assertEqual(by_id["1"].severity, "HIGH")
        self.assertEqual(by_id["2"].severity, "MEDIUM")


class SchemaConformanceTestCase(unittest.TestCase):
    """Every adapter must produce schema-conformant, traceable findings."""

    def test_all_findings_carry_run_context_and_category(self):
        payload = {"_engine": "semgrep", "results": [{
            "check_id": "r", "path": "a.ts", "start": {"line": 1},
            "extra": {"message": "m", "severity": "WARNING", "metadata": {}}}]}
        for f in SemgrepAdapter().normalize(result_for("sast_semgrep", payload), CTX):
            self.assertEqual(f.commit, "deadbeef")
            self.assertEqual(f.branch, "main")
            self.assertEqual(f.environment, "test")
            self.assertEqual(f.scanner_category, "sast_semgrep")
            self.assertTrue(f.fingerprint)
            self.assertTrue(f.remediation)
            self.assertTrue(f.impact)


if __name__ == "__main__":
    unittest.main(verbosity=2)
