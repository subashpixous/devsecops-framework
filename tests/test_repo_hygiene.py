"""Contract tests for repository hygiene and web server configuration.

Both categories exist because no code scanner has an opinion about the files they
read. That makes their failure modes specific:

  * they must never invent findings from UNTRACKED files -- a log on a
    developer's disk is not an exposure, and noise is how a control gets
    switched off;
  * they must never publish what they found. An upload filename can identify the
    person who submitted the document, and these reports are downloadable;
  * an empty payload from a broken run must mark the result FAILED, not report a
    clean repository.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.adapters.repo_hygiene_adapter import RepoHygieneAdapter  # noqa: E402
from framework.adapters.web_config_adapter import WebConfigAdapter  # noqa: E402
from framework.collectors.base import ScannerResult  # noqa: E402
from framework.collectors.repo_hygiene import (  # noqa: E402
    RepoHygieneCollector,
    under_upload_dir,
    under_web_root,
    upload_root,
)
from framework.collectors.web_config import WebConfigCollector  # noqa: E402
from framework.core.context import RunContext  # noqa: E402
from framework.core.toolrunner import run, tool_available  # noqa: E402

CTX = RunContext(commit="deadbeef", branch="main", environment="test")


def result_with(category, payload, tool):
    result = ScannerResult(tool=tool, category_key=category)
    result.payload = payload
    if payload is not None:
        result.succeed()
    return result


class GitRepo:
    """A real git repository, so the collector is tested through git itself."""

    def __init__(self, tracked, untracked=()):
        self.root = tempfile.mkdtemp(prefix="hygiene-test-")
        self._write(tracked)
        self._write(untracked)
        run(["git", "init", "-q"], cwd=self.root)
        run(["git", "config", "user.email", "t@example.invalid"], cwd=self.root)
        run(["git", "config", "user.name", "t"], cwd=self.root)
        for relative in tracked:
            run(["git", "add", "--", relative], cwd=self.root)
        run(["git", "commit", "-q", "-m", "t", "--no-gpg-sign"], cwd=self.root)

    def _write(self, files):
        for relative in files:
            path = os.path.join(self.root, relative.replace("/", os.sep))
            os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


@unittest.skipUnless(tool_available("git"), "git is required for these tests")
class RepoHygieneCollectorTestCase(unittest.TestCase):
    def collect(self, tracked, untracked=()):
        repo = GitRepo(tracked, untracked)
        self.addCleanup(repo.cleanup)
        result = RepoHygieneCollector(workspace=repo.root).collect()
        rules = [issue["rule"] for issue in (result.payload or {}).get("issues", [])]
        return result, rules, result.payload or {}

    def test_untracked_files_never_produce_a_finding(self):
        _, rules, _ = self.collect(
            tracked=[".gitignore", "app/index.php"],
            untracked=["public/error_log", ".env", "storage/uploads/scan.jpg"],
        )
        self.assertEqual(
            rules, [],
            "untracked files are not published and must not be reported as exposure",
        )

    def test_log_inside_the_web_root_is_high_and_named_as_reachable(self):
        _, rules, payload = self.collect([".gitignore", "public/error_log"])
        self.assertIn("committed-runtime-log-in-webroot", rules)
        issue = [i for i in payload["issues"] if i["rule"] == "committed-runtime-log-in-webroot"][0]
        self.assertEqual(issue["severity"], "HIGH")
        self.assertIn("over HTTP", issue["description"])

    def test_log_outside_the_web_root_is_lower_severity(self):
        _, rules, payload = self.collect([".gitignore", "logs/app.log"])
        issue = [i for i in payload["issues"] if i["rule"] == "committed-runtime-log"][0]
        self.assertEqual(issue["severity"], "LOW")

    def test_missing_gitignore_is_reported(self):
        _, rules, _ = self.collect(["app/index.php"])
        self.assertIn("missing-gitignore", rules)

    def test_present_gitignore_is_not_reported(self):
        _, rules, _ = self.collect([".gitignore", "app/index.php"])
        self.assertNotIn("missing-gitignore", rules)

    def test_env_file_is_critical_and_example_env_is_not(self):
        _, rules, _ = self.collect([".gitignore", ".env"])
        self.assertIn("environment-file-committed", rules)
        _, clean_rules, _ = self.collect([".gitignore", ".env.example"])
        self.assertNotIn("environment-file-committed", clean_rules)

    def test_private_key_is_critical(self):
        _, _, payload = self.collect([".gitignore", "deploy/id_rsa"])
        issue = [i for i in payload["issues"] if i["rule"] == "key-material-committed"][0]
        self.assertEqual(issue["severity"], "CRITICAL")
        # Rotation before removal: history is public the moment it is pushed.
        self.assertIn("rotate", issue["remediation"].lower())

    def test_schema_sql_outside_the_web_root_is_not_a_finding(self):
        _, rules, _ = self.collect([".gitignore", "database/schema.sql"])
        self.assertNotIn("database-file-in-webroot", rules)

    def test_sql_inside_the_web_root_is_a_finding(self):
        _, rules, _ = self.collect([".gitignore", "public/dump.sql"])
        self.assertIn("database-file-in-webroot", rules)

    def test_uploaded_documents_are_aggregated_and_never_named(self):
        _, _, payload = self.collect([
            ".gitignore",
            "storage/uploads/app_1/aadhaar_front.jpg",
            "storage/uploads/app_1/photo.jpg",
            "storage/uploads/app_2/certificate.pdf",
        ])
        issues = [i for i in payload["issues"] if i["rule"] == "user-uploaded-documents-committed"]
        self.assertEqual(len(issues), 1, "per-submission directories must collapse to one finding")
        issue = issues[0]
        self.assertEqual(issue["count"], 3)
        self.assertEqual(issue["severity"], "CRITICAL")
        blob = " ".join(str(v) for v in issue.values())
        for leaked in ("aadhaar_front.jpg", "photo.jpg", "certificate.pdf"):
            self.assertNotIn(
                leaked, blob,
                "an upload filename can identify a person and must not reach the report",
            )

    def test_a_non_git_workspace_fails_rather_than_reporting_clean(self):
        directory = tempfile.mkdtemp(prefix="hygiene-nogit-")
        self.addCleanup(shutil.rmtree, directory, True)
        result = RepoHygieneCollector(workspace=directory).collect()
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.is_trustworthy)
        self.assertIn("NOT assessed", " ".join(result.errors))


class RepoHygieneAdapterTestCase(unittest.TestCase):
    def test_empty_payload_marks_the_result_failed(self):
        result = result_with("repo_hygiene", None, "repo-hygiene")
        findings = RepoHygieneAdapter().normalize(result, CTX)
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "FAILED")

    def test_payload_without_issues_array_is_untrusted(self):
        result = result_with("repo_hygiene", {"unexpected": True}, "repo-hygiene")
        RepoHygieneAdapter().normalize(result, CTX)
        self.assertEqual(result.status, "FAILED")

    def test_personal_data_and_server_disclosure_get_different_categories(self):
        result = result_with("repo_hygiene", {"issues": [
            {"rule": "user-uploaded-documents-committed", "severity": "CRITICAL",
             "file": "storage/uploads", "count": 40, "title": "t"},
            {"rule": "committed-runtime-log-in-webroot", "severity": "HIGH",
             "file": "public/error_log", "count": 1, "title": "t"},
        ]}, "repo-hygiene")
        findings = RepoHygieneAdapter().normalize(result, CTX)
        categories = {f.rule: f.category for f in findings}
        self.assertEqual(categories["user-uploaded-documents-committed"], "sensitive_data_exposure")
        self.assertEqual(categories["committed-runtime-log-in-webroot"], "information_disclosure")

    def test_findings_are_stamped_with_the_run_context(self):
        result = result_with("repo_hygiene", {"issues": [
            {"rule": "missing-gitignore", "severity": "MEDIUM", "file": ".gitignore",
             "count": 1, "title": "t"},
        ]}, "repo-hygiene")
        finding = RepoHygieneAdapter().normalize(result, CTX)[0]
        self.assertEqual(finding.commit, "deadbeef")
        self.assertEqual(finding.branch, "main")

    def test_evidence_states_scale_without_naming_files(self):
        result = result_with("repo_hygiene", {"issues": [
            {"rule": "user-uploaded-documents-committed", "severity": "CRITICAL",
             "file": "storage/uploads", "count": 275, "title": "t"},
        ]}, "repo-hygiene")
        finding = RepoHygieneAdapter().normalize(result, CTX)[0]
        self.assertIn("275 files", finding.evidence)


class PathHelperTestCase(unittest.TestCase):
    def test_web_root_detection(self):
        self.assertTrue(under_web_root("portal/public/error_log"))
        self.assertFalse(under_web_root("portal/logs/error_log"))

    def test_upload_detection_and_grouping(self):
        self.assertTrue(under_upload_dir("portal/storage/uploads/app_1/x.jpg"))
        # Grouping stops at the deepest RECOGNISED upload directory. `app_1` is a
        # per-submission directory, not an upload directory, so it must not
        # become its own group -- otherwise an application that creates one
        # directory per applicant produces one finding per applicant.
        self.assertEqual(upload_root("portal/storage/uploads/app_1/x.jpg"),
                         "portal/storage/uploads")

    def test_a_file_directly_in_the_web_root_directory_counts(self):
        self.assertTrue(under_web_root("public/index.php"))

    def test_static_assets_are_not_mistaken_for_user_submissions(self):
        # Shipped BY the project, not sent TO it. Raising a personal-data breach
        # for a published guidelines PDF is the kind of false positive that
        # makes a team stop believing the true ones.
        self.assertFalse(under_upload_dir("portal/public/assets/files/guidelines.pdf"))
        self.assertFalse(under_upload_dir("public/static/media/logo.png"))
        self.assertFalse(under_upload_dir("public/assets/documents/terms.pdf"))

    def test_real_submissions_are_still_detected(self):
        self.assertTrue(under_upload_dir("portal/storage/uploads/app_1/scan.jpg"))
        self.assertTrue(under_upload_dir("var/documents/applicant.pdf"))

    def test_the_directory_itself_is_not_matched_as_its_own_parent(self):
        self.assertFalse(under_web_root("public"))


class WebConfigCollectorTestCase(unittest.TestCase):
    def collect(self, files):
        directory = tempfile.mkdtemp(prefix="webconfig-test-")
        self.addCleanup(shutil.rmtree, directory, True)
        for relative, content in files.items():
            path = os.path.join(directory, relative.replace("/", os.sep))
            os.makedirs(os.path.dirname(path) or directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        result = WebConfigCollector(
            workspace=directory, web_server_config_files=list(files)
        ).collect()
        return result, [i["rule"] for i in (result.payload or {}).get("issues", [])]

    def test_unguarded_upload_directory_is_critical(self):
        result, rules = self.collect({"storage/uploads/.htaccess": "Options -Indexes\n"})
        self.assertIn("upload-directory-executes-code", rules)
        issue = [i for i in result.payload["issues"]
                 if i["rule"] == "upload-directory-executes-code"][0]
        self.assertEqual(issue["severity"], "CRITICAL")

    def test_an_upload_directory_that_disables_the_php_engine_is_not_flagged(self):
        _, rules = self.collect({"storage/uploads/.htaccess": "php_flag engine off\n"})
        self.assertNotIn("upload-directory-executes-code", rules)

    def test_an_upload_directory_that_denies_everything_is_not_flagged(self):
        _, rules = self.collect({"storage/uploads/.htaccess": "Require all denied\n"})
        self.assertNotIn("upload-directory-executes-code", rules)

    def test_directory_listing_enabled_is_reported(self):
        _, rules = self.collect({"public/.htaccess": "Options +Indexes\nRedirectMatch 404 /\\.git\n"})
        self.assertIn("directory-listing-enabled", rules)

    def test_listing_in_an_upload_directory_is_more_severe(self):
        result, _ = self.collect({"storage/uploads/.htaccess": "php_flag engine off\nOptions +Indexes\n"})
        issue = [i for i in result.payload["issues"] if i["rule"] == "directory-listing-enabled"][0]
        self.assertEqual(issue["severity"], "HIGH")

    def test_nginx_autoindex_is_recognised(self):
        _, rules = self.collect({"public/nginx.conf": "server {\n  autoindex on;\n}\n"})
        self.assertIn("directory-listing-enabled", rules)

    def test_webroot_without_deny_rules_is_reported(self):
        _, rules = self.collect({"public/.htaccess": "Options -Indexes\n"})
        self.assertIn("sensitive-extensions-not-denied", rules)

    def test_webroot_with_deny_rules_is_not_reported(self):
        _, rules = self.collect({
            "public/.htaccess": 'Options -Indexes\n<FilesMatch "\\.(env|log|sql)$">\nRequire all denied\n</FilesMatch>\n'
        })
        self.assertNotIn("sensitive-extensions-not-denied", rules)

    def test_no_config_files_supplied_fails_rather_than_passing(self):
        result = WebConfigCollector(workspace=".", web_server_config_files=[]).collect()
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.is_trustworthy)

    def test_an_unreadable_config_degrades_the_result(self):
        directory = tempfile.mkdtemp(prefix="webconfig-empty-")
        self.addCleanup(shutil.rmtree, directory, True)
        with open(os.path.join(directory, ".htaccess"), "w", encoding="utf-8") as handle:
            handle.write("")
        result = WebConfigCollector(
            workspace=directory, web_server_config_files=[".htaccess"]
        ).collect()
        self.assertFalse(result.is_trustworthy)


class WebConfigAdapterTestCase(unittest.TestCase):
    def test_empty_payload_marks_the_result_failed(self):
        result = result_with("web_server_config", None, "web-config")
        self.assertEqual(WebConfigAdapter().normalize(result, CTX), [])
        self.assertEqual(result.status, "FAILED")

    def test_issues_normalise_as_misconfiguration_with_a_cwe(self):
        result = result_with("web_server_config", {"issues": [
            {"rule": "upload-directory-executes-code", "severity": "CRITICAL",
             "file": "storage/uploads/.htaccess", "title": "t", "description": "d"},
        ]}, "web-config")
        finding = WebConfigAdapter().normalize(result, CTX)[0]
        self.assertEqual(finding.category, "misconfiguration")
        self.assertEqual(finding.cwe, "CWE-434")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_a_malformed_record_degrades_rather_than_being_dropped(self):
        result = result_with("web_server_config", {"issues": [None]}, "web-config")
        WebConfigAdapter().normalize(result, CTX)
        self.assertFalse(result.is_trustworthy)


if __name__ == "__main__":
    unittest.main()
