"""Common schema, SonarQube adapter and project detector tests."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.adapters.sonarqube_adapter import SonarQubeAdapter, quality_gate_summary  # noqa: E402
from framework.collectors.base import ScannerResult  # noqa: E402
from framework.collectors.sonarqube import redact_host, resolve_project_key  # noqa: E402
from framework.core.context import RunContext, established  # noqa: E402
from framework.core.schema import (  # noqa: E402
    APPROVED_SCHEMA_KEYS,
    Finding,
    compute_fingerprint,
    normalise_severity,
    severity_breakdown,
)
from framework.detect.detector import detect  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sonarqube-sample.json")


class SchemaTestCase(unittest.TestCase):
    def test_approved_keys_present_and_ordered_first(self):
        finding = Finding(tool="t", category="vulnerability", description="d", file="f.ts")
        keys = list(finding.to_dict().keys())
        self.assertEqual(keys[: len(APPROVED_SCHEMA_KEYS)], APPROVED_SCHEMA_KEYS)

    def test_severity_normalisation_covers_scanner_vocabularies(self):
        self.assertEqual(normalise_severity("BLOCKER"), "CRITICAL")
        self.assertEqual(normalise_severity("MAJOR"), "MEDIUM")
        self.assertEqual(normalise_severity("MINOR"), "LOW")
        self.assertEqual(normalise_severity("HIGH"), "HIGH")
        self.assertEqual(normalise_severity("moderate"), "MEDIUM")

    def test_unrecognised_severity_becomes_unknown_not_info(self):
        self.assertEqual(normalise_severity("wat"), "UNKNOWN")
        self.assertEqual(normalise_severity(None), "UNKNOWN")

    def test_fingerprint_is_stable_across_line_moves(self):
        first = compute_fingerprint("sonarqube", "S2068", "src/a.ts", "vulnerability", "Hard-coded password")
        second = compute_fingerprint("sonarqube", "S2068", "src/a.ts", "vulnerability", "  hard-coded   PASSWORD ")
        self.assertEqual(first, second)

    def test_fingerprint_differs_across_files(self):
        first = compute_fingerprint("sonarqube", "S2068", "src/a.ts", "vulnerability", "x")
        second = compute_fingerprint("sonarqube", "S2068", "src/b.ts", "vulnerability", "x")
        self.assertNotEqual(first, second)

    def test_severity_breakdown_always_lists_every_level(self):
        counts = severity_breakdown([])
        self.assertEqual(set(counts), {"CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW", "INFO"})

    def test_not_established_rendering(self):
        self.assertEqual(established(""), "NOT_ESTABLISHED")
        self.assertEqual(established("  "), "NOT_ESTABLISHED")
        self.assertEqual(established("prod"), "prod")

    def test_context_renders_blank_fields_as_not_established(self):
        payload = RunContext().to_dict()
        self.assertEqual(payload["deployed_url"], "NOT_ESTABLISHED")
        self.assertEqual(payload["environment"], "NOT_ESTABLISHED")


class AdapterTestCase(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, "r", encoding="utf-8") as handle:
            self.payload = json.load(handle)
        self.result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
        self.result.payload = self.payload
        self.result.succeed()
        self.context = RunContext(commit="deadbeef", branch="main", environment="production")
        self.adapter = SonarQubeAdapter()

    def test_normalises_issues_and_hotspots(self):
        findings = self.adapter.normalize(self.result, self.context)
        categories = {f.category for f in findings}
        self.assertIn("vulnerability", categories)
        self.assertIn("security_hotspot", categories)
        self.assertIn("code_smell", categories)

    def test_stamps_run_context_on_every_finding(self):
        for finding in self.adapter.normalize(self.result, self.context):
            self.assertEqual(finding.commit, "deadbeef")
            self.assertEqual(finding.branch, "main")
            self.assertEqual(finding.environment, "production")

    def test_maps_cwe_and_owasp_from_rule_standards(self):
        findings = self.adapter.normalize(self.result, self.context)
        vulnerability = next(f for f in findings if f.rule == "typescript:S2068")
        self.assertIn("CWE-798", vulnerability.cwe)
        self.assertIn("A7:2021", vulnerability.owasp)

    def test_component_path_is_stripped_of_project_key(self):
        findings = self.adapter.normalize(self.result, self.context)
        self.assertTrue(any(f.file == "UI/src/app/services/auth.service.ts" for f in findings))
        self.assertFalse(any(":" in f.file for f in findings))

    def test_impact_severity_wins_over_legacy_severity(self):
        findings = self.adapter.normalize(self.result, self.context)
        issue = next(f for f in findings if f.native_id == "AY-impact-1")
        self.assertEqual(issue.severity, "HIGH")

    def test_hotspot_status_maps_to_review(self):
        findings = self.adapter.normalize(self.result, self.context)
        hotspot = next(f for f in findings if f.category == "security_hotspot")
        self.assertEqual(hotspot.status, "TO_REVIEW")
        self.assertTrue(hotspot.is_open)

    def test_empty_payload_marks_result_failed_not_clean(self):
        result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
        result.payload = None
        findings = SonarQubeAdapter().normalize(result, self.context)
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "FAILED")

    def test_missing_issues_array_marks_result_failed(self):
        result = ScannerResult(tool="sonarqube", category_key="sast_sonarqube")
        result.payload = {"quality_gate": {}}
        result.succeed()
        SonarQubeAdapter().normalize(result, self.context)
        self.assertEqual(result.status, "FAILED")

    def test_quality_gate_summary_extracts_failing_conditions(self):
        summary = quality_gate_summary(self.payload["quality_gate"])
        self.assertEqual(summary["status"], "ERROR")
        self.assertEqual(len(summary["failing_conditions"]), 1)

    def test_absent_quality_gate_is_unknown_not_ok(self):
        self.assertEqual(quality_gate_summary(None)["status"], "UNKNOWN")
        self.assertEqual(quality_gate_summary({})["status"], "UNKNOWN")


class CollectorHelperTestCase(unittest.TestCase):
    def test_redact_host_strips_credentials(self):
        self.assertEqual(redact_host("https://user:secret@sonar.example.com:9000/x"), "https://sonar.example.com:9000")

    def test_project_key_resolution_from_properties_file(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "sonar-project.properties"), "w", encoding="utf-8") as handle:
                handle.write("# comment\nsonar.projectKey=my-key\n")
            key, source = resolve_project_key(workspace)
            self.assertEqual(key, "my-key")
            self.assertEqual(source, "sonar-project.properties")

    def test_project_key_not_established_when_absent(self):
        with tempfile.TemporaryDirectory() as workspace:
            key, source = resolve_project_key(workspace)
            self.assertEqual(key, "")
            self.assertEqual(source, "NOT_ESTABLISHED")

    def test_explicit_project_key_wins(self):
        with tempfile.TemporaryDirectory() as workspace:
            key, source = resolve_project_key(workspace, "explicit")
            self.assertEqual(key, "explicit")
            self.assertEqual(source, "explicit input")


class DetectorTestCase(unittest.TestCase):
    def test_detects_a_generic_node_and_docker_project(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({"dependencies": {"react": "18.0.0", "express": "4.0.0"}}, handle)
            with open(os.path.join(workspace, "Dockerfile"), "w", encoding="utf-8") as handle:
                handle.write("FROM node:20\n")
            capabilities = detect(workspace)
            self.assertIn("npm", capabilities["package_manager"])
            self.assertIn("react", capabilities["frameworks"])
            self.assertIn("express", capabilities["frameworks"])
            self.assertTrue(capabilities["docker"])
            self.assertTrue(capabilities["frontend"])
            self.assertTrue(capabilities["backend"])

    def test_detects_terraform_as_iac(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "main.tf"), "w", encoding="utf-8") as handle:
                handle.write('resource "aws_s3_bucket" "b" {}\n')
            capabilities = detect(workspace)
            self.assertTrue(capabilities["iac"])
            self.assertIn("terraform", capabilities["iac_types"])

    def test_detects_openapi_specification_file(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "openapi.json"), "w", encoding="utf-8") as handle:
                json.dump({"openapi": "3.0.0", "paths": {}}, handle)
            capabilities = detect(workspace)
            self.assertTrue(capabilities["openapi"])
            self.assertEqual(capabilities["openapi_spec_files"], ["openapi.json"])

    def test_detects_kubernetes_manifest(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "deploy.yaml"), "w", encoding="utf-8") as handle:
                handle.write("apiVersion: apps/v1\nkind: Deployment\n")
            capabilities = detect(workspace)
            self.assertTrue(capabilities["kubernetes"])

    def test_unknown_values_stay_empty_never_guessed(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "package.json"), "w", encoding="utf-8") as handle:
                json.dump({}, handle)
            capabilities = detect(workspace)
            self.assertEqual(capabilities["cloud"], "")
            self.assertEqual(capabilities["deployed_url"], "")
            self.assertEqual(capabilities["deployment_target"], "")
            self.assertFalse(capabilities["authenticated_testing_available"])
            self.assertEqual(capabilities["authenticated_testing_source"], "NOT_ESTABLISHED")

    def test_dotnet_project_is_detected_as_backend(self):
        with tempfile.TemporaryDirectory() as workspace:
            with open(os.path.join(workspace, "Api.csproj"), "w", encoding="utf-8") as handle:
                handle.write('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
                             "<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
            capabilities = detect(workspace)
            self.assertIn("nuget", capabilities["package_manager"])
            self.assertIn("aspnet-core", capabilities["frameworks"])
            self.assertTrue(capabilities["backend"])

    def test_explicit_overrides_are_recorded(self):
        with tempfile.TemporaryDirectory() as workspace:
            capabilities = detect(workspace, {"deployed_url": "https://example.test"})
            self.assertEqual(capabilities["deployed_url"], "https://example.test")
            self.assertIn("deployed_url", capabilities["overridden_fields"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
