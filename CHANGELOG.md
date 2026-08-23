# Changelog

All notable changes to this framework are recorded here. Releases are immutable
tags; callers pin a tag or SHA, and rollback means repinning the previous one.

## [0.3.0] - 2026-08-23

Findings that were reported but carried no verdict weight now count. Both fixes
came from the first real run against a consumer project.

### Fixed - Checkov filed every finding under Infrastructure-as-Code

Checkov covers three different concerns, and all three were adapted into
`iac_scanning`. That category is `NOT_APPLICABLE` on a project with no IaC, so on
the validation project **26 findings were reported and none of them gated**:

| Rule | Count | What it actually is |
|---|---|---|
| `CKV_SECRET_6` | 22 | committed secrets, not IaC |
| `CKV_DOCKER_3` | 2 | container runs as root |
| `CKV_DOCKER_2` | 2 | no HEALTHCHECK |

All 26 also carried `severity: UNKNOWN`, and the policy threshold for UNKNOWN is
0 - so routed correctly they would have forced a FAILED verdict on their own.

Checkov is now scanned once per concern, each scoped with `--framework` and each
registered to the category that owns it:

    checkov-iac         -> iac_scanning
    checkov-secrets     -> secret_scanning
    checkov-dockerfile  -> container_hardening   (new category)

`container_hardening` is a new PRE_BUILD category, applicable when the project has
a Dockerfile. It reads build definitions from source, so it needs no built image -
which is why container root-user findings previously had nowhere applicable to go.

Severity, evidence and line numbers are preserved, and **no finding is dropped by
the routing**. A secret finding's `component` is now the file that carries it
rather than Checkov's hash of the matched value, which had made every secret look
like a distinct component and hid which files were affected.

Secret hygiene extends to Checkov: `code_block`, `fixed_definition`, `details` and
`evaluations` are stripped at collection, and the adapter refuses any record still
carrying them - the same two-layer contract Gitleaks already had.

### Fixed - one unparseable file silenced an entire SAST category

Semgrep reports rule failures and per-file parse failures in the same `errors`
array. The collector treated both as lost coverage, so 5 unparseable files pushed
`sast_semgrep` to `NOT_VERIFIED` and **48 real findings, 11 of them HIGH, stopped
gating.**

Root cause: Semgrep's generic HTML and JSON grammars cannot parse Angular template
dialect - interpolation such as `{{ counter < 10 ? '0' + counter : counter }}`,
bare `&`, and `&&` inside bindings. These are parser limitations on 5 files, not
rule failures, and every other file scanned normally.

Errors are now classified. A blocking error still degrades the result. A parse
error that **names the file it could not read** is recorded as a bounded coverage
gap: that file was not analysed, the rest of the scan stands, and the gap travels
into the report as a limitation.

Two interlocks keep this fail-closed, and no rule was disabled to achieve it:

* An error that does not name a file bounds nothing, so it is treated as blocking.
* A bounded gap **plus zero findings** degrades anyway - "clean" cannot be trusted
  while files went unread.

`ScannerResult.warn()` was added for this: a caveat that is recorded and reported
without setting `degraded`. `partial()`, `fail()` and `skip()` are unchanged and
still degrade.

### Fixed - fingerprints collided, so one exception suppressed many findings

`compute_fingerprint` hashed tool + rule + file + category + description and
deliberately excluded position, so unrelated edits could not churn identities.
Measured against a real project that trade was wrong: **83 of 156 findings shared
an identity across 21 groups.** Five different credentials on five different lines
of one file collapsed into one id, so a single `accepted_risk` entry would have
suppressed all five - and the largest group was 11.

Fingerprints now include an occurrence discriminator built from `native_id`,
`line` and `component`. All three are needed against real output: `line`
separates repeated hits of one rule, and `component` separates one CVE affecting
two packages, which share a file, a line of 0 and a native id.

Checkov had no per-occurrence id at all - `native_id` was the check id, which
repeats for every hit. For a secret check it is now Checkov's hash of the matched
value, which identifies the occurrence and survives the line moving; otherwise it
falls back to `check_id:path:line`.

Replaying the real 156-finding dataset through the new scheme: **156 unique
fingerprints, 0 collisions**, down from 94 unique / 83 colliding.

The churn this originally avoided is accepted. Churn costs accuracy in the
NEW/EXISTING split; collision silently hides real findings. Only one of those is a
safety property.

### Tests

157, up from 126. `tests/test_routing.py` covers routing per concern, that no
finding is dropped, that a secret's component is never its value hash, Checkov
secret stripping and adapter refusal, error classification including the
unattributable-error case, and the collector's degradation matrix - notably that a
parse gap with findings stays OK while a parse gap with none fails closed. It
also covers fingerprint uniqueness, stability under repeat runs, and the property
that motivated the fix: an exception targeting one finding suppresses exactly one.

A new CI guard asserts independent findings receive independent fingerprints, so
the collision cannot regress.

## [0.2.2] — 2026-08-22

Supply-chain hardening. Closes the 6 HIGH findings the framework raised against
its own workflows during runner validation.

### Fixed — third-party actions pinned to immutable commit SHAs

Semgrep rule `yaml.github-actions.security.github-actions-mutable-action-tag`
flagged 6 HIGH findings: every `actions/*` reference used a mutable major tag.
A tag can be silently repointed at different code; a SHA cannot.

| Action | Was | Now | Release |
|---|---|---|---|
| `actions/checkout` | `@v4` | `@11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/setup-python` | `@v5` | `@a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `actions/upload-artifact` | `@v4` | `@ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |

Each SHA was resolved from the action's own repository, confirmed to be a real
commit there, and cross-checked against the precise semver tag pointing at it.
No SHA was guessed. Major versions are unchanged, so runtime behaviour is
identical.

`docs/ARCHITECTURE.md` no longer describes this as a known gap and now documents
the verification procedure for re-resolving a pin.

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
