# Architecture

## Design constraints

1. The framework wraps a lifecycle; it never enters it. It does not build, deploy,
   or modify the project under analysis.
2. It is universal. Nothing in `framework/` may reference a specific repository,
   organisation, or stack. CI asserts this.
3. It fails safe. Every unknown resolves toward `NOT_VERIFIED`, never toward `PASS`.
4. It is honest. A category that was not tested says so, in every output format.

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
               report -> final-report.json
                         report.md
                         security-report.pdf
                    |
              upload artifact (always)
```

## Module map

| Module | Responsibility | May not |
|---|---|---|
| `core/schema.py` | The one finding shape every tool normalises into; fingerprinting; severity normalisation | know about any specific tool |
| `core/categories.py` | The complete security category matrix and applicability rules | know about any specific project |
| `core/status_engine.py` | The four statuses and the verdict rules | perform I/O |
| `core/policy.py` | Threshold and required-control data | contain logic branches per project |
| `core/registry.py` | Binds tools to categories; the Phase 2–6 extension point | import collectors eagerly |
| `core/manual_controls.py` | The controls automation cannot cover | ever be marked tested by the framework |
| `detect/detector.py` | Evidence-based capability detection | guess a value it cannot establish |
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

## Supply chain

Third-party actions in this repository are currently referenced by version tag,
**not** by SHA. This is a known gap; pin before treating the workflows as
production-hardened:

```bash
gh api repos/actions/checkout/git/ref/tags/v4      --jq .object.sha
gh api repos/actions/setup-python/git/ref/tags/v5  --jq .object.sha
gh api repos/actions/upload-artifact/git/ref/tags/v4 --jq .object.sha
# then: uses: actions/checkout@<sha>  # v4
```

The framework itself is pinned correctly: callers reference a tag or SHA, and the
reusable workflow checks out framework code at `github.job_workflow_sha`, so the
workflow definition and the code that runs can never drift apart.

## Rollback

| Layer | Action |
|---|---|
| A project | Delete its `.github/workflows/security.yml`. Nothing else changes. |
| A bad framework release | Repin the caller to the previous tag/SHA. |
| Delivery | Unaffected. The security workflow has no `needs:` relationship with any build or deploy workflow, in either direction. |
