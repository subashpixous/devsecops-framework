# Architecture

## Design constraints

1. The framework wraps a lifecycle; it never enters it. It does not build, deploy,
   or modify the project under analysis.
2. It is universal. Nothing in `framework/` may reference a specific repository,
   organisation, or stack. CI asserts this.
3. It fails safe. Every unknown resolves toward `NOT_VERIFIED`, never toward `PASS`.
4. It is honest. A category that was not tested says so, in every output format.
5. It finishes. A security finding is a result to publish, never a reason to stop.
   The only things that may terminate a run are the framework failing at its own
   job, and an evidence set that contradicts itself.

## Pipeline

```
        caller workflow (thin, per project)
                    |
        security-pipeline.yml (reusable, workflow_call)
                    |
   +----------------+----------------+
   |                                 |
checkout project             checkout framework @ job_workflow_sha
   |                                 |
   +----------------+----------------+
                    |
              framework self-test        <- invariants must pass first
                    |
              detect  ->  capabilities.json
                    |
              collect ->  <tool>.json          (raw evidence, read-only)
                    |
             normalize -> normalized-findings.json   (common schema)
                    |
              evaluate -> status engine
                    |
             readiness -> deployment decision
                    |
               report -> final-report.json
                         report.md
                         security-report.pdf
                    |
              upload artifact (always)
```

## Pipeline stages

Categories carry a `stage`, and `--stage` selects which run. This exists because
the inputs each stage needs appear at different points in a delivery pipeline:

| Stage | Needs | Categories |
|---|---|---|
| `PRE_BUILD` | source only | SonarQube, Semgrep, Gitleaks, Trivy SCA, Checkov (IaC / secrets / dockerfile), 42Crunch |
| `POST_BUILD` | a built artifact | Trivy image, SBOM, bundle scanner, cosign, Trivy k8s |
| `AGGREGATION` | findings from this run | finding lifecycle |
| `POST_DEPLOY` | a live URL | ZAP, Nuclei, runtime probes |
| `CLOUD` | cloud credentials | Prowler, IAM Access Analyzer |

A category outside the executed stages resolves to `NOT_VERIFIED` with that
reason. It never resolves to PASS, and it is never silently omitted.

## Finding lifecycle (Phase 4)

```
current findings + baseline(normalized-findings.json) + exceptions
                              │
        ┌─────────────────────┴──────────────────────┐
   in baseline?                                 in exceptions?
        │                                             │
   yes → EXISTING                        expired/undated → EXPIRED_EXCEPTION
   no  → NEW                                            (NOT suppressed)
        │                                    valid → FALSE_POSITIVE
   in baseline but absent now:                       ACCEPTED_RISK
        scanner ran OK → FIXED                        (suppressed)
        scanner failed → UNKNOWN
```

Two rules are load-bearing:

* **An expired suppression does not suppress.** An exception with no expiry
  date is treated as expired. Without a review point, accepted risk decays into
  permanent silent acceptance.
* **`FIXED` requires a successful scanner.** If the scanner that originally
  produced a finding did not complete, its absence is `UNKNOWN`. A broken
  scanner must never look like remediation.

## Six independent results

The status engine answers "did the security controls pass". That question has one
honest answer and this framework has always given it. It is the wrong question to
gate a pipeline on, and gating on it is what this design fixes: a consumer with
nothing better to key on writes `if SECURITY != PASS: exit 1`, the run dies at
the first finding, and every stage that would have published that finding is
skipped. The finding becomes *less* visible, not more.

So there are six results, and none is derived from another:

| Result | Owner | Answers |
|---|---|---|
| `PIPELINE` | `cli.py` | Did the framework finish its own job? |
| `SECURITY` | `core/status_engine.py` | Did the security controls pass? |
| `EVIDENCE` | `core/readiness.py` | Can this run's evidence be relied on? |
| `READINESS` | `core/readiness.py` | Of what was measured, how much passed? |
| `ASSURANCE` | `core/readiness.py` | How much was measured at all? |
| `DECISION` | `core/readiness.py` | Should this ship? |

`SECURITY` is unchanged and still fail-closed. What changed is that a pipeline
gates on `DECISION`, published as a workflow output, rather than on the CI exit
status.

## Readiness scoring

One dimension per **applicable** security category, derived from
`CATEGORY_REGISTRY` itself so a new scanner joins readiness with no code change,
plus seven framework-level dimensions: build, unit tests, test coverage, source
file coverage, scanner execution, evidence integrity, outstanding risk.

```
readiness = 100 x sum(score x weight for MEASURED dimensions)
                / sum(weight     for MEASURED dimensions)
assurance = 100 x sum(weight MEASURED)
                / (sum(weight MEASURED) + sum(weight UNKNOWN))
```

| Dimension state | Numerator | Denominator | Assurance denominator |
|---|---|---|---|
| `PASS` / `FAILED` / `PARTIAL` | score x weight | weight | weight |
| `NOT_VERIFIED` / `NOT_TESTED` / `NOT_REPORTED` | -- | -- | weight |
| `NOT_APPLICABLE` | -- | -- | -- |

The middle row is the load-bearing one. An unmeasured dimension earns nothing
**and is not dropped**, so no arrangement of untested controls can produce a high
assurance figure. Dropping them instead -- the obvious implementation -- would
make a run that checked one thing report 100%, which is exactly the false
confidence the rest of this framework exists to prevent.

`NOT_APPLICABLE` is the only state that leaves both sums. A project with no
Dockerfile is neither credited nor penalised for having no container findings.

Scores are never `0.0` for an unmeasured dimension; the field is `None` and
renders as `--`. "Scored zero" and "never scored" are different facts and no
output format may render them the same way.

## Decision resolution

Evaluated top to bottom, first match wins. The order encodes what outranks what:

```
evidence contradicts itself         -> UNKNOWN      (deployment not permitted)
nothing measured at all             -> UNKNOWN
assurance < unknown_below_assurance -> UNKNOWN
any blocking condition              -> NOT_READY
assurance < minimum_assurance       -> CONDITIONALLY_READY
readiness < ready_threshold, or any
  outstanding condition             -> CONDITIONALLY_READY
otherwise                           -> READY
```

An untrustworthy evidence set outranks everything because a decision drawn from
it would be arbitrary. `UNKNOWN` never permits deployment; it is not a pass.

**What blocks:** a failed build, a failed test suite, a failed *required*
control, an expired suppression, open `CRITICAL` findings over threshold, and a
self-contradictory evidence set.

**What merely costs:** everything else, including `HIGH` findings. They lower the
score and appear as outstanding conditions -- visible and expensive, but not a
termination. Risk is accepted through the exceptions file with an owner and an
expiry date. There is no other mechanism, and an undated exception suppresses
nothing.

Weights, risk points and thresholds are data in `framework/policy/default-policy.yml`.
They are printed in every report next to the figure they produced, so any
percentage can be recomputed by hand from the published dimension table.

## Module map

| Module | Responsibility | May not |
|---|---|---|
| `core/schema.py` | The one finding shape every tool normalises into; fingerprinting; severity normalisation | know about any specific tool |
| `core/categories.py` | The complete security category matrix and applicability rules | know about any specific project |
| `core/status_engine.py` | The four statuses and the verdict rules | perform I/O |
| `core/readiness.py` | Readiness dimensions, the two percentages, the deployment decision | change a security verdict, or read a finding except through a policy-defined rule |
| `core/policy.py` | Threshold and required-control data | contain logic branches per project |
| `core/registry.py` | Binds tools to categories; the Phase 2–6 extension point | import collectors eagerly |
| `core/manual_controls.py` | The controls automation cannot cover | ever be marked tested by the framework |
| `detect/detector.py` | Evidence-based capability detection | guess a value it cannot establish |
| `core/toolrunner.py` | One execution path for external tools: availability, timeout, exit-code semantics, redaction | raise; leak a secret into captured output |
| `core/lifecycle.py` | NEW/EXISTING/FIXED/suppression/expiry | suppress an expired exception |
| `core/secretpatterns.py` | Shared detectors for built and live bundles | return a matched secret value |
| `collectors/*` | Talk to one scanner backend each | decide a verdict, or raise past their boundary |
| `adapters/*` | Pure payload → findings transformation | perform network I/O |
| `report/*` | Render `final-report.json` | recompute or reinterpret a status |

## Status resolution

Resolution order per category, evaluated top to bottom:

```
capability rule says not applicable   -> NOT_APPLICABLE
category.phase > policy.active_phase  -> NOT_IMPLEMENTED   (blocking notes retained)
no scanner result for the category    -> NOT_VERIFIED
scanner status != OK, or has errors   -> NOT_VERIFIED
findings breach thresholds, or the
  upstream gate is ERROR              -> FAILED
otherwise                             -> PASS
```

Top-level `SECURITY`:

```
any applicable category FAILED                  -> FAILED
any required category not PASS                  -> NOT_VERIFIED
otherwise                                       -> PASS (scoped)
```

`FAILED` outranks `NOT_VERIFIED` because a confirmed failure is a stronger and
more actionable statement than an unknown. Unverified controls are still listed
in the rationale and in the category matrix — they are never treated as passing.

A `PASS` is always emitted together with `verdict_scope`
(e.g. `PHASE_1[sast_sonarqube]`) and `coverage_complete: false`, so it can never
be read as "this application is secure".

## Applicability and the deployed URL

`deployable` categories (DAST, Nuclei, runtime probes) stay **applicable** when
`deployed_url` is unknown. Marking them `NOT_APPLICABLE` would erase a real gap.
Instead the obstacle is recorded as a blocking note that travels into the report.

## Extension model

Adding a scanner never changes the engine:

1. Write a `Collector` returning a `ScannerResult`.
2. Write an `Adapter` mapping its payload into `Finding`.
3. `register_scanner(ScannerRegistration(...))` against an existing category key.
4. Move that category's `phase` down to the active phase.

The category already exists and is already being reported as `NOT_IMPLEMENTED`,
so the change is additive by construction.

## Finding routing

A scanner that covers several concerns must not file every finding under one
category. The category decides whether a finding carries verdict weight, so a
misfiled finding can be reported and still count for nothing -- for example a
committed secret filed under Infrastructure-as-Code on a project that has no IaC,
where the category is `NOT_APPLICABLE`.

The rule: **a finding belongs to the category that owns its concern, not to the
tool that happened to find it.** Where a tool can be scoped, each concern gets its
own scan, its own `ScannerResult` and its own category:

| Tool | Scope | Category |
|---|---|---|
| `checkov-iac` | `--framework <iac>` | `iac_scanning` |
| `checkov-secrets` | `--framework secrets` | `secret_scanning` |
| `checkov-dockerfile` | `--framework dockerfile` | `container_hardening` |
| `trivy-sca` / `-image` / `-sbom` / `-k8s` | subcommand | four categories |

The engine keys scanner results by `result.category_key` and findings by
`finding.scanner_category`, so the two travel independently and a finding always
lands where it counts.

## Scanner degradation vs coverage gaps

`ScannerResult` distinguishes two things a scan can report about itself:

* `partial()` / `fail()` / `skip()` set `degraded`, and the category becomes
  `NOT_VERIFIED`. Use these whenever the result can no longer be trusted.
* `warn()` records a **bounded, named** caveat without degrading -- for example
  specific files a parser could not read while the rest of the scan completed.

The distinction exists because collapsing the two discards real findings: one
unparseable template would push an entire SAST category to `NOT_VERIFIED`, so
every genuine finding stopped gating. A bounded gap is reported as a limitation
instead.

Two rules keep this fail-closed:

* An unattributable error -- one that does not name what it could not read --
  is always treated as blocking, never as a bounded gap.
* A bounded gap **plus zero findings** degrades anyway. "Clean" cannot be trusted
  while files went unread.

## Secret hygiene

Findings end up in a downloadable CI artifact, so no code path may place a
credential in one. Enforced at four points:

1. **Gitleaks** — `Secret` and `Match` stripped in the collector, before the
   payload is attached to the result. A length and a redaction flag are kept.
2. **Gitleaks adapter** — refuses to normalise any record still carrying those
   fields, and fails the result instead. A stripping regression fails loudly
   rather than publishing secrets.
3. **Bundle and runtime scanners** — report `len=N sha256:<12 hex>`, never the
   value. Two occurrences can be correlated; neither can be recovered.
4. **Tool runner** — redacts known secret-bearing environment variable values
   and generic key shapes from all captured stdout/stderr.

Additionally: Trivy's secret scanner is disabled (it embeds raw values, and
Gitleaks owns the category); Semgrep's `extra.lines` matched source is dropped;
ZAP `evidence` and Nuclei `extracted-results` response echoes are dropped.

## Supply chain

Every third-party action is pinned to an **immutable full 40-character commit
SHA**. A tag can be silently repointed at different code; a SHA cannot.

| Action | Pinned SHA | Release |
|---|---|---|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |

The trailing `# vX.Y.Z` comment on each `uses:` line records which release the SHA
corresponds to, so the pin stays readable and auditable.

To re-resolve or update a pin, resolve the tag and confirm the SHA is a real
commit in that repository before using it:

```bash
gh api repos/actions/checkout/git/ref/tags/v4 --jq .object.sha
gh api repos/actions/checkout/commits/<sha> --jq .commit.message   # must exist
gh api "repos/actions/checkout/tags?per_page=100"   --jq '.[] | select(.commit.sha=="<sha>") | .name'                # which release
```

Never pin a SHA that has not been verified to exist in the action's own
repository.

The framework itself is pinned the same way: callers reference a tag or SHA, and
the reusable workflow checks out framework code at `github.job_workflow_sha`, so
the workflow definition and the code that runs can never drift apart.

## Rollback

| Layer | Action |
|---|---|
| The readiness model | Set `fail_on: security` in the caller. Exit codes 2 and 3 return, and the readiness block is still published alongside them. |
| A project | Delete its `.github/workflows/security.yml`. Nothing else changes. |
| A bad framework release | Repin the caller to the previous tag/SHA. |
| Delivery | Unaffected. The security workflow has no `needs:` relationship with any build or deploy workflow, in either direction. |
