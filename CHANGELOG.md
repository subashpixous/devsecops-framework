# Changelog

All notable changes to this framework are recorded here. Releases are immutable
tags; callers pin a tag or SHA, and rollback means repinning the previous one.

## [0.2.1] — 2026-08-22

Fixes from the first real GitHub Actions runner validation. One of them is a
false-PASS defect and is the reason this release exists.

### Fixed — CRITICAL: `succeed()` erased a recorded degradation (false PASS)

Runner run `32592212680` reported:

```
Dependency / SCA ......... PASS
  note: no lockfile or manifest was recognised; coverage may be incomplete
```

Nothing was scanned, yet the category passed — exactly the failure mode this
framework exists to prevent.

Two interacting bugs in `ScannerResult`:

1. `partial()` guarded on `status != FAILED`. `FAILED` is also the fail-closed
   *initial* value, so `partial()` never actually set `PARTIAL` on a fresh
   result — it only appended a warning.
2. `succeed()` then promoted to `OK` whenever `errors` was empty. `partial()`
   records a **warning**, never an error, so every partially-degraded scan was
   silently upgraded to fully trusted and `is_trustworthy` returned `True`.

**Blast radius: 11 of 15 collector modules call `partial()` then `succeed()`.**

Fix:

- `ScannerResult` gains an explicit `degraded` flag, set by `fail()`,
  `partial()` and `skip()`.
- `succeed()` promotes to `OK` only when there are no errors **and** nothing is
  degraded. The fail-closed default still lets a genuinely clean run reach `OK`.
- `partial()` now keys off recorded errors rather than status, so it reports
  `PARTIAL` instead of being swallowed.
- `replay()` added for the self-test payload-injection path.
- `degraded` is surfaced on every scanner record in every report.

Verified on the runner: the same project now yields `trivy-sca` = `PARTIAL`,
`is_trustworthy` = `False`, `sca_dependencies` = `NOT_VERIFIED`.

### Fixed — Trivy omits `Results` on a clean scan

Trivy returns `rc=0`, `SchemaVersion 2` and **no `Results` key** when a completed
scan has nothing to report — for example a pip project whose requirements are
unpinned ranges, so no concrete package version resolves. The adapter treated
that as "output cannot be trusted" and blamed a healthy tool.

A payload carrying `SchemaVersion` but no `Results` is now zero findings; a
payload without `SchemaVersion` is still a real failure. The collector's
`PARTIAL` warning keeps the category at `NOT_VERIFIED`, so the verdict is
unchanged — only the reported reason became accurate.

### Fixed — trivy install pinned a tag that does not exist

`TRIVY_VERSION` was `0.58.2`; tag `v0.58.2` returns 404 from the GitHub API.
Pinned to `0.74.0` (asset verified) and switched from `curl | sh` to the direct
release-tarball pattern already used by gitleaks and nuclei, which also removes
a pipe-to-shell from the supply chain.

### Fixed — timezone-dependent lifecycle tests

`tests/test_lifecycle.py` built expiry fixtures from the **local** calendar while
the framework evaluates expiry in **UTC**. Where local runs ahead of UTC,
yesterday-local is still today-UTC and two expiry tests failed. The framework is
correct — UTC is deterministic regardless of where CI runs — so the fixtures now
use UTC. This never failed on the runner, which is UTC; it was a local-only flake.

### Added

- `.github/workflows/pipeline-validation.yml` — calls the reusable pipeline by
  full external reference, the way a consumer does, so the cross-repository
  resolution path, scanner installation and artifact upload are exercised in CI.
  `security-pipeline.yml` is `workflow_call`-only and would otherwise never run.

### Tests

126, up from 119. Five new regression tests lock the `degraded` invariant in;
two cover the Trivy `Results` semantics.

## [0.2.0] — 2026-08-22

The complete approved pipeline. Phases 2 through 6 implemented; Phase 1
retained unchanged.

### Added — scanners (13 new, 16 total)

| Category | Tool | Notes |
|---|---|---|
| SAST | Semgrep / OpenGrep | Auto-falls back to `opengrep`; records which engine ran. Matched source text is deliberately **not** copied into findings — Semgrep rulesets include secret detection. |
| Secret scanning | Gitleaks | `Secret`/`Match` stripped at collection, before anything reaches disk. Scans git history when the workspace is a repo. |
| Dependency / SCA | Trivy `fs` | Trivy's own secret scanner is disabled: Gitleaks owns that category, and Trivy's secret output embeds raw values. |
| IaC | Checkov | Absent severity normalises to `UNKNOWN`, which fails closed. |
| API specification | 42Crunch | Credential-gated; without a token the category is `NOT_VERIFIED`, never substituted. |
| Container image | Trivy `image` | Requires an explicit `images` input; never guesses a tag. |
| SBOM | Trivy CycloneDX | Emits `sbom.cdx.json` as a first-class artifact. Produces no findings by design. |
| Frontend bundle secrets | framework-native | Scans built output for keys, tokens, connection strings, internal hosts, stack traces and shipped source maps. |
| Artifact signing | cosign / Sigstore | **Verify-only; never signs.** Distinguishes "unsigned" from "could not verify". |
| Kubernetes | Trivy `config` | Workload misconfiguration. |
| DAST | OWASP ZAP | Baseline (passive) by default; `full` active scan is opt-in and warns. Native script or container. |
| Known exposures | Nuclei | Excludes `dos`, `fuzz`, `intrusive` and `brute-force` templates. |
| Runtime probes | framework-native | TLS posture and expiry, HTTP→HTTPS redirect, six security headers, cookie flags, CORS wildcard and origin reflection, version disclosure, exposed debug surfaces, stack traces in error responses, and live JavaScript bundle validation. GET-only; no payloads, no fuzzing, no writes. |
| Cloud posture | Prowler | Read-only assessment; credential-gated per provider. |
| IAM external access | AWS Access Analyzer | Read-only `list-*`. **An absent analyzer is itself reported as a finding** — no analyzer means AWS is not evaluating external access at all. |

### Added — Phase 4 finding lifecycle

- `core/lifecycle.py`: NEW / EXISTING / FIXED / FALSE_POSITIVE / ACCEPTED_RISK /
  EXPIRED_EXCEPTION / UNKNOWN, computed against a previous
  `normalized-findings.json`.
- **An exception with no expiry date, or a past one, is EXPIRED and does not
  suppress.** The `finding_lifecycle` category reports FAILED when any
  suppression has expired.
- **`FIXED` requires that the scanner which found the item ran successfully.**
  Otherwise the item is `UNKNOWN`, so a broken scanner can never look like
  remediation.
- `framework/policy/exceptions.example.yml` documents the format.

### Added — pipeline stages

- Categories now carry a `stage`: `PRE_BUILD`, `POST_BUILD`, `AGGREGATION`,
  `POST_DEPLOY`, `CLOUD`.
- `--stage` selects which run, so each stage can be wired to the point in an
  existing pipeline where its inputs exist. A category outside the executed
  stages reports `NOT_VERIFIED`, not PASS.

### Added — infrastructure

- `core/toolrunner.py`: one execution path for every external tool — availability
  checks, timeouts, retries, "findings present" exit-code handling, and secret
  redaction of captured output. Never raises.
- `core/secretpatterns.py`: shared detectors for the build-time and live bundle
  scanners, with entropy gating and placeholder filtering to keep false
  positives low. Returns a length and SHA-256 prefix, **never the matched value**.
- `cli.py tools`: reports registered scanners and which binaries are present.
- `registry.import_failures()`: a collector module that fails to load is surfaced
  as a limitation rather than silently absent.

### Changed

- Default policy `active_phase` 1 → 6; required categories now
  `sast_sonarqube`, `sast_semgrep`, `secret_scanning`.
- `security_finding_categories` extended to all 17 scanner finding classes.
- Threshold evaluation excludes only *valid* suppressions.
- Reports (JSON, Markdown, PDF) gained a finding-aggregation section and a
  lifecycle state column; `schema_version` 1 → 2.
- Reusable workflow gained 26 inputs, 6 optional secrets, 8 outputs, and
  best-effort scanner installation — a tool that fails to install makes its
  category `NOT_VERIFIED` and never fails the job.

### Tests

119 tests, up from 57. New suites cover the lifecycle invariants, tool-runner
redaction, secret-pattern hygiene, Gitleaks secret stripping (including a
defence-in-depth test that the adapter refuses a record still carrying a
secret), missing-input behaviour for all seven gated collectors, empty and
malformed payload handling for all eleven adapters, and output conformance for
each adapter.

CI additionally asserts: no mutating HTTP verb in read-only collectors; no
project identifier anywhere in `framework/`; every registered scanner resolves a
collector and adapter; every category is covered or explicitly
framework-internal; detection is correct across eight stack fixtures; and a run
with no scanners installed produces all three reports and does **not** report
PASS.

### Known gaps

- Third-party GitHub Actions are referenced by version tag, not SHA. See
  `docs/ARCHITECTURE.md` → Supply chain.
- 42Crunch, Prowler, IAM Access Analyzer and cosign verification are
  credential-gated. Without credentials they report `NOT_VERIFIED` with the
  exact missing input named. This is by design, not an omission.

## [0.1.0] — 2026-08-21

Phase 1. First release: common finding schema, security category matrix, status
engine, read-only SonarQube collector and adapter, project detector, policy,
manual controls, JSON/Markdown/PDF reporting, reusable workflow, 57 invariant
tests.
