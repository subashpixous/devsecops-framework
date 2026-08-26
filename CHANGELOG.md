# Changelog

All notable changes to this framework are recorded here. Releases are immutable
tags; callers pin a tag or SHA, and rollback means repinning the previous one.

## [0.6.0] - 2026-08-26

Deployment-readiness release. One behaviour change, stated plainly:

**A security finding no longer stops the pipeline. Nothing is suppressed to
achieve that.**

### The problem this fixes

The framework has always defaulted to non-blocking, and always emitted exactly
one security verdict: `PASS` / `FAILED` / `NOT_VERIFIED`. That single conflated
signal was the only thing a consumer could gate on, so consumers wrote the only
gate it supports:

```python
if security_status != "PASS":
    sys.exit(1)
```

The pipeline then died at the first finding, and every stage after it was
skipped -- the remaining scanners, the evidence pack, the consolidated report,
the artifact upload. **The finding that "blocked" the pipeline ended up less
visible, not more.** The verdict was correct; keying a pipeline on it was not,
and the framework offered nothing better.

### Added - deployment readiness and an explicit deployment decision

`framework/core/readiness.py` computes six results that are siblings, none
derived from another:

| Result | Values |
|---|---|
| `PIPELINE` | `COMPLETED` / `COMPLETED_WITH_ERRORS` / `INCOMPLETE` |
| `SECURITY` | `PASS` / `FAILED` / `NOT_VERIFIED` -- **unchanged** |
| `EVIDENCE` | `COMPLETE` / `INCOMPLETE` / `UNTRUSTWORTHY` |
| `READINESS` | percent of measured weight that passed |
| `ASSURANCE` | percent of total weight that was measured at all |
| `DECISION` | `READY` / `CONDITIONALLY_READY` / `NOT_READY` / `UNKNOWN` |

Readiness is scored over one dimension per applicable security category --
derived from the category registry itself, so a new scanner joins readiness with
no code change and no per-project branching -- plus build, unit tests, test
coverage, source file coverage, scanner execution, evidence integrity and
outstanding risk.

### The rule that keeps the number honest

An unmeasured dimension earns nothing **and is not dropped**. It leaves the
readiness numerator and denominator, and its weight moves to the assurance
denominator:

```
readiness = 100 x sum(score x weight for MEASURED dimensions)
                / sum(weight     for MEASURED dimensions)
assurance = 100 x sum(weight MEASURED)
                / (sum(weight MEASURED) + sum(weight UNKNOWN))
```

A run that measured one dimension and passed it reports `readiness 100% /
assurance 8%` and can never reach `READY`. There is no arrangement of
`NOT_TESTED`, `NOT_VERIFIED`, `NOT_REPORTED` or `SCANNER_FAILED` that yields a
high assurance figure. `NOT_APPLICABLE` is the one state that leaves both sums:
a project with no Dockerfile is neither credited nor penalised for it.

Every figure is recomputable by hand from the published dimension table. Weights,
risk points and thresholds are data in `default-policy.yml`, printed in every
report next to the number they produced. `tests/test_readiness.py` asserts the
recomputation.

### What blocks, and what merely costs

Only a `CRITICAL` finding over threshold blocks on its own, alongside a failed
build, a failed test suite, a failed required control, and a self-contradictory
evidence set. A `HIGH` finding lowers the score and is listed as an outstanding
condition: visible, costly, and not a termination. Risk is accepted through the
exceptions file with an owner and an expiry date -- there is no other mechanism,
and an undated exception still suppresses nothing.

### Added - evidence integrity as a first-class check

The evidence set is now checked for self-consistency, and a contradiction is
blocking:

* a scanner reporting `OK` while carrying a recorded degradation
* a category reported `PASS` while a scanner serving it did not complete
* findings filed under a category with no recorded scanner execution

Any of these forces `EVIDENCE = UNTRUSTWORTHY` and `DECISION = UNKNOWN`. This is
the one class of failure that is *more* serious than a failed scan: a failed scan
is a known gap, while a report that contradicts itself makes every other number
in it unreliable.

### Added - caller-reported test signals

`--test-status` and `--test-coverage-percent`, plumbed through the reusable
workflow as `test_status` and `test_coverage_percent`. Never inferred. An
unreported value is `NOT_REPORTED`; an unparseable coverage figure is
`NOT_REPORTED` rather than zero, because zero scores and unknown must not.

### Added - `--fail-on`, replacing `--fail-on-security`

`never` (default) / `evidence` / `decision` / `security`. New exit codes `5`
(decision not READY) and `6` (evidence untrustworthy). `--fail-on-security` and
the `fail_on_security` workflow input still work and still mean exactly what they
meant; they are deprecated in favour of gating a deployment job on the new
`deployment_decision` and `deployment_permitted` outputs.

### Added - the consolidated report

`report.md` and the PDF now open with an executive summary and a Deployment
Readiness Summary written for a reader who reads no other section, followed by
the full readiness calculation, the deployment decision with its rationale, and a
remediation plan ordered by urgency rather than by scanner. `final-report.json`
gains `readiness` and `pipeline` blocks; `evidence-manifest.json` records the
decision and the complete calculation, so an auditor can recompute the percentage
from the evidence pack alone.

Report ordering changed so all five formats stay consistent: when the evidence
manifest fails to assemble, the reports are re-rendered with the corrected
pipeline status and the manifest is rebuilt over what is actually on disk.

### Unchanged, deliberately

Every existing guarantee. The 20-category registry, the status engine and its
verdict rules, the four original statuses, `SECURITY = FAILED` and what produces
it, the fail-closed resolution order, the coverage census and its six buckets,
the per-scanner census, suppression expiry, `FIXED` requiring a successful
scanner, the immutable framework SHA assertion, secret stripping, project
neutrality, and all 444 pre-existing tests -- which still pass, unmodified.

No threshold was lowered, no rule weakened, no finding suppressed, no severity
downgraded, and no scanner state relabelled. The security verdict this framework
produces is bit-for-bit the verdict it produced before; what changed is that a
pipeline no longer has to die to report it.

## [0.5.0] - 2026-08-24

Production-readiness release. Three defects meant consumers received less than
this repository contained; four additions make each run prove what it checked.

### Fixed - the shipped workflow ran the framework one phase behind itself

`security-pipeline.yml` declared `active_phase: 6` while `default-policy.yml`
declared 7. The CLI lets the workflow value override the policy, so for every
consumer using the reusable workflow with defaults, `repo_hygiene` and
`web_server_config` reported NOT_IMPLEMENTED and their collectors never ran.

Those are the two categories v0.4.0 was released for. The behaviour was correct
for a phase that has not shipped, and completely wrong for one that had.

Reproduced on a sample project: phase 7 produced 3 findings, phase 6 produced 0.

`tests/test_release_consistency.py` now asserts the workflow default equals the
policy value, and that no implemented category sits above it. This defect class
is invisible to Python tests because it lives in the seam between the code and
the artefacts that ship it.

### Fixed - the example every integrator copies was two releases stale

`examples/caller-workflow.yml` pinned `@v0.2.0` while `docs/ONBOARDING.md`
instructs integrators to copy that file verbatim. Anyone following the
documentation got a framework with no SARIF, no CSV, no coverage census and no
phase-7 categories. Now pinned to the current release, and asserted by test.

### Fixed - documentation understated the control set

README claimed 17 security categories; the registry declares 20. Asserted.

### Added - SonarQube analysis identity and freshness

SonarQube is the one scanner this framework does not execute: it reads results
someone else produced, at some other time, over some other revision. Nothing
verified that those results described the code under validation, which was the
last remaining path to a PASS that did not describe the scanned commit.

The collector now reads `/api/project_analyses/search` and compares the analysis
revision against the commit being validated. Four states are reported verbatim:

| State | Meaning | Can reach PASS |
|---|---|---|
| `SONARQUBE_SCAN_COMPLETED` | analysis covers this commit | yes |
| `SONARQUBE_RESULT_STALE` | analysis describes different code | **no** |
| `SONARQUBE_RESULT_UNAVAILABLE` | no usable analysis retrieved | **no** |
| `SONARQUBE_PERMISSION_ERROR` | token rejected (401/403) | **no** |

A revision match is authoritative at any age; a mismatch is stale at any age.
Only where the server reports no revision does age decide, and the report says
so -- an age-based assurance is not proof of revision identity, and the two are
never presented as the same claim.

Stale findings are still reported. They are real findings about real code, just
not this commit's code, and deleting them would lose evidence.

Also collected: quality gate, project measures (coverage, duplication, ncloc,
issue counts) and the file list the analysis actually covered.

### Added - per-scanner coverage transparency

The census answered "did anything miss every scanner?". It could not answer
"what did THIS scanner look at?" -- the question asked whenever a finding is
absent and someone needs to know whether it was ever looked for.

Every scanner now reports its own reach: files analysed, files excluded by its
own path policy, files outside the types it parses, and files it would have read
but did not. Each carries exactly one status: `analysed`, `scanner_unavailable`,
`scanner_failed`, `not_applicable` or `coverage_not_declared`.

Two rules keep it honest:

  * A scanner with no declared file-level reach reports `n/a`, never `0`. OWASP
    ZAP does not read files; "0 of 149 analysed" would invent a gap, and
    inventing gaps discredits the real ones.
  * Gitleaks now declares its reach BEFORE the availability guard, so a missing
    gitleaks can state how much coverage was lost instead of leaving it
    unquantified. The census still credits coverage only to scans that
    completed, so declaring intent early cannot inflate anything.

SonarQube declares the files its analysis covered, read from
`/api/components/tree`. Previously the census counted Semgrep alone, so coverage
read 0% whenever Semgrep failed even though a full SonarQube analysis had
succeeded.

### Added - exploitability enrichment (EPSS + CISA KEV)

Severity answers "how bad if exploited". It does not answer "is anyone
exploiting it", and 400 findings sorted by severity is a list nobody triages.

`framework/core/prioritization.py` attaches EPSS exploit probabilities and CISA
KEV known-exploited status. Three constraints:

  * **Never fabricated.** A CVE with no score gets no score -- not 0.0, which
    would sort it as harmless. `findings.csv` renders `NOT_ESTABLISHED` when the
    source was unreachable and `NO_SCORE` when it was reachable but held no
    entry for that CVE.
  * **Never mandatory.** Both are third-party network calls. Failure degrades
    the report, never the run: `EPSS_UNAVAILABLE` / `KEV_UNAVAILABLE` are
    reported and findings pass through untouched. `--no-enrichment` disables
    both; `--epss-file` / `--kev-file` support air-gapped runners.
  * **Never a verdict input.** Enrichment orders findings; it does not decide
    them. A verdict that depends on a third-party API is a verdict that changes
    during that API's outage.

### Added - cross-scanner corroboration

When SonarQube and Semgrep both find the SQL injection on line 42, the report
now says `Detected by: sonarqube + semgrep`.

Correlation is **additive**: nothing is merged, renamed or dropped. Two engines
agreeing is stronger evidence than one, and deleting a row deletes that. It also
avoids reintroducing the fingerprint-collision failure this framework already
fixed once -- merged findings share an identity, and one exception entry would
then silently suppress a second scanner's evidence that nobody reviewed.

Linking is deliberately conservative: same file AND a shared CWE AND within
three lines. Findings without a CWE never correlate, because "two findings in
the same file" is not evidence they are the same defect, and a wrong link is
worse than no link. One scanner reporting twice is repetition, not confirmation.

### Added - run evidence manifest

`evidence-manifest.json` records what would let someone else reproduce the
verdict: repository, commit, branch, framework and scanner versions, policy
identity and thresholds, per-scanner exit codes and durations, the SonarQube
analysis identity, the coverage census, the verdict, the limitations carried
verbatim, and a SHA-256 of every artefact produced.

It states its own limits: the digests establish that the artefacts have not
changed since the run that wrote them. They are **not** signatures and do not
establish authenticity -- anyone who can modify the artefacts can recompute the
digests. A manifest that looks cryptographic without being so is worse than one
that says plainly what it is.

### Added - supply-chain hardening of the framework itself

  * Scanner downloads are checksum-verified against the checksums file published
    with the same release. This catches the realistic failure mode: a truncated
    or corrupted download installing a broken scanner that reports nothing. It
    does **not** defend against a compromised upstream release, and the workflow
    comment says so rather than implying otherwise.
  * cosign is pinned to a version instead of `releases/latest`. A floating
    download makes the evidence manifest record a version nobody chose, and
    cosign is the tool that verifies everyone else's signatures.
  * `requirements.txt` is pinned exactly (`==`). A security tool that resolves
    its own dependencies to "whatever is newest today" cannot say which code
    produced a verdict.
  * Tests assert all three, plus that every third-party action stays pinned to a
    full commit SHA and that the pipeline grants no write scope beyond
    `security-events`.

### Tests

255 -> 343. New suites: `test_sonarqube.py` (31 -- the collector had none),
`test_prioritization.py` (26), `test_correlation.py` (21), `test_evidence.py`
(18), `test_release_consistency.py` (15).

One existing assertion changed. `test_a_result_without_a_declaration_contributes_nothing`
asserted that an undeclared scanner was absent from the census list; it now
asserts the scanner is listed but credited with nothing. The test name always
described the real invariant -- contributes nothing -- and a scanner that
vanishes from the census is exactly the silent gap the census exists to prevent.

## [0.4.0] - 2026-08-24

File-level coverage, two categories for what code scanners cannot see, and
findings delivered where developers actually work.

Note: v0.3.0 was tagged but `VERSION` and `framework.__version__` were left at
0.2.2. This release corrects them; reports from a 0.3.0 run understate their own
framework version.

### Fixed - the SCA scanner was excluded from the only directory it needed

`SKIP_DIRS` in the Trivy collector and `EXCLUDES` in the Semgrep collector were
two hard-coded lists that both contained `vendor`. For SAST that is a reasonable
default. For SCA it is the defect:

    vendor/          <- where composer, go mod and bundler put dependencies
    node_modules/    <- where npm puts them

A PHP or Go project with no committed lockfile keeps its ONLY inventory of
installed third-party versions inside `vendor/`. Trivy was told to skip it, found
no manifest anywhere else, and returned no `Results` section. The collector
called that "no lockfile recognised" - a scan of nothing, reported as a scan.

Path policy now lives in `framework/core/scanpaths.py` and is resolved from the
caller's INTENT rather than a shared list:

| Intent | Vendored dependency source | Why |
|---|---|---|
| `sca` | read | it is the dependency inventory |
| `secret` | read | a credential is exposed wherever it sits |
| `sast` | skipped, and declared | findings in uneditable code bury the rest |

A skipped tree is never silent: `ExclusionPlan.coverage_note()` names the
directory and the reason, and it travels into the report.

`--include-dependencies` runs SAST over vendored source too. Either way the
choice is recorded, so a result never has to be interpreted against an assumed
default.

### Fixed - Semgrep ran the ruleset that does not look for security defects

The default was `p/default`, Semgrep's high-precision starter pack. It is tuned
to almost never produce a false positive, which also means it does not ask most
security questions. A category could reach PASS from a scan that never looked.

The default is now `p/security-audit` + `p/owasp-top-ten`, plus a language pack
for each language actually detected (`p/php`, `p/python`, ...). `SEMGREP_RULES`
still overrides, and `config_source` on the result records which applied.

### Fixed - a plain PHP application declared itself out of scope for DAST

`backend` was inferred only from a framework signature (Laravel, Django, ...).
A PHP application without one was `backend: false`, so `applies_when="deployable"`
resolved every runtime category to NOT_APPLICABLE. An internet-facing application
excused itself from runtime testing.

PHP source has one execution mode: interpreted by a web server on request. A
`.php` file in the tree now establishes `backend`.

### Added - file-level coverage census

The category model answers "which control ran". It cannot answer "was any of my
code never looked at", because a scanner that completes over half a repository
reports identically to one that read all of it.

`framework/core/coverage.py` walks the workspace and puts every file in exactly
one bucket, each with a reason:

    analysed                  read by a scanner that completed
    excluded_path             matched a declared exclusion (the pattern is named)
    no_scanner_for_filetype   no engine here parses this type (.sql, .htaccess)
    scanner_did_not_complete  the engine that reads it failed or was absent
    not_code                  images, fonts, archives - data, not source

Rules that keep the number honest:

  * a scanner that FAILED or went PARTIAL is credited with nothing. Its files
    surface as unanalysed rather than being attributed to a scan that never read
    them;
  * secret scanning does not count as analysis. Gitleaks reads every byte of a
    PHP file and still says nothing about the injection in it. Its reach is
    reported separately;
  * an absent census reads as UNKNOWN, never as complete.

Written to `final-report.json`, section 8.1 of `report.md` and section 7.3 of the
PDF.

### Added - `repo_hygiene` category

What the repository DISCLOSES, as opposed to what its code does. Every other
scanner reads these files as opaque data and reports nothing:

  * runtime logs committed inside a web root, fetchable over HTTP;
  * database dumps, archives and `.env` files served from the web root;
  * private keys and credential files, reported by name without opening them;
  * user-uploaded documents committed alongside the application;
  * the missing `.gitignore` behind all of the above.

Only TRACKED files are examined. An untracked file on a developer's disk is not
an exposure, and inventing findings for build output is how a control gets
switched off.

Uploaded personal data is reported per directory and never per file. An upload
filename can identify the person who submitted it, and these reports are
downloadable artifacts. Static-asset paths (`assets/`, `static/`, ...) are
excluded: a published guidelines PDF is shipped BY the project, not sent TO it.

### Added - `web_server_config` category

`.htaccess`, `nginx.conf` and `web.config` decide questions no application
hardening can answer - whether the upload directory executes what it is given,
whether directory listings are served, whether logs and dumps are denied. No SAST
engine parses them.

A MISSING deny rule is the finding: an upload directory with no configuration is
the default-permissive case, and the default is what runs.

### Added - SARIF output and code scanning upload

`security.sarif` is written every run, and the reusable workflow uploads it via
`github/codeql-action/upload-sarif`. Findings appear on their line in the pull
request and in the Security tab instead of inside an artifact nobody downloads.

  * `partialFingerprints` carries the framework fingerprint, so a finding stays
    one alert across runs instead of re-raising on every reformat;
  * `suppressions` carries FALSE_POSITIVE and ACCEPTED_RISK. EXPIRED is
    deliberately absent - expiry exists to force the decision back into view;
  * a finding with no file location is emitted against the repository root, never
    dropped;
  * incomplete category coverage and unanalysed files are emitted as
    `toolExecutionNotifications`, so the file cannot be mistaken for a clean scan.

The job now requests `security-events: write`. A caller that cannot grant it sets
`upload_sarif: false`; the step is `continue-on-error`, because code scanning
being unavailable is a delivery problem and must never become a security verdict.

### Added - `findings.csv`

The narrative reports truncate by design: 400 table rows and 60 detail entries in
Markdown, 250 and 40 in the PDF. On a legacy codebase that is a small fraction of
the findings, and no untruncated list existed in a format anyone opens.

`findings.csv` has one row per finding, never truncated, sorted most-severe-first
with NEW ahead of EXISTING inside each severity, and empty `owner`, `target_date`
and `notes` columns. Written through the `csv` module, so a description
containing a comma or a quote cannot shift the columns.

`--max-table-rows` and `--max-detailed-findings` now raise the narrative limits.

### Changed

  * `active_phase` default is 7.
  * `sensitive_data_exposure` added to `security_finding_categories`. It is kept
    apart from `information_disclosure` because the remediations are unrelated:
    one is fixed by moving a file, the other by rotating a secret.
  * The detector reports `web_server_config_files`.
  * `test_all_phases_are_active_by_default` asserts against the category registry
    instead of a hard-coded 6, which failed for the one reason that is not a
    defect.

### Tests

157 -> 255. New suites: `test_scanpaths.py`, `test_coverage.py`,
`test_repo_hygiene.py`, `test_report_outputs.py`.

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
