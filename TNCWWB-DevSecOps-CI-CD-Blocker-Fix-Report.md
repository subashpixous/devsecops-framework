# TNCWWB DevSecOps CI/CD Blocker Fix Report

**Framework:** `devsecops-framework` @ branch `feat/production-readiness-v0.5.0` (base `1385219`)
**Application:** `TNCWWB---Non-Member-board-application` — **not modified** (`git status`: 0 changes)
**Date:** 2026-08-25
**Tests:** 405 → **424**, all passing
**Commit / Push / Tag:** **NONE** — stopped for review as instructed

---

## 0. READ THIS FIRST — what is and is not proven

Two blockers are **proven fixed by execution**. Two are **fixed by code but validated only in CI**, and I will not claim otherwise.

| Blocker | Fix | Proof status |
|---|---|---|
| **FD-2** scanner install | ✅ Fixed | **PROVEN LOCALLY.** Old script reproduced the exact 4 failures; new script passes all 6 through the identical harness |
| **FD-1** version pinning | ✅ Fixed | **PROVEN by inspection + 5 tests.** Cannot fall back to a branch; asserts what it checked out |
| **FD-3** PHP rules | ✅ Root cause identified with certainty; patterns rewritten; **accounting fixed** | **RULE COMPILATION NOT VERIFIED LOCALLY.** Semgrep cannot run here (see below). The accounting fix — which is the part that matters for truthfulness — **is** proven by 8 tests |
| **FD-4** v0.5.0 tag | ⚠️ Diagnosed, **not actioned** | Creating a tag is a git write; you said do not tag |
| **SonarQube** | ✅ Diagnosed precisely + framework now names the missing permission | Server-side change is yours to make |

### Why FD-3 rule compilation is not locally verified

Semgrep will not install on this machine, and I tried:

```
ERROR: Could not find a version that satisfies the requirement semgrep (from versions: none)
=> SEMGREP STILL UNAVAILABLE (network/platform blocked)
```

PyPI is unreachable from this environment (TLS interception), and Semgrep has no native Windows support. **The pipeline's own `semgrep --test` gate is the validation.** Expect it to flag residual pattern issues on first run — that is the gate working, not the fix failing.

**Per your instruction, no rule is marked EXECUTED anywhere in this work.** The framework now reports `EXECUTED: 0` when the engine did not run, which is what the local TNCWWB scan produced.

---

## 1. FD-1 — Framework version pinning

### Caller side (already fixed — verified)

`TNCWWB/.github/workflows/security-validation.yml`:

| Line | Value |
|---|---|
| 259 `uses:` | `...security-pipeline.yml@138521946feeda98a2cba47e8a7fe0715b0eb388` |
| 279 `framework_ref:` | `138521946feeda98a2cba47e8a7fe0715b0eb388` |

Both pin the same immutable SHA, and that SHA **equals framework HEAD**. ✅ **Production is not on `main`.**

### Framework side — the residual risk I fixed

The framework still resolved:

```yaml
ref: ${{ github.job_workflow_sha || inputs.framework_ref }}   # framework_ref default: "main"
```

If `job_workflow_sha` were ever empty and a caller omitted `framework_ref`, the pipeline would **silently validate a project against whatever was on `main`**. A verdict produced by an unknown framework revision is not evidence of anything.

**Three changes:**

1. **`framework_ref` default `"main"` → `""`.** Fail closed instead of guessing.
2. **New step "Resolve the framework revision (fail closed)"** — resolves `job_workflow_sha` → `inputs.framework_ref`, and **hard-errors** if neither is set *or* if the value is `main`/`master`/`HEAD`/`refs/heads/*`.
3. **New step "Assert the framework revision that is actually checked out"** — compares `git rev-parse HEAD` against the requested ref (resolving tags to commits), exports `FRAMEWORK_SHA`, and fails on mismatch. Checkout not erroring is not proof it fetched what was asked for.

The verified SHA now lands in `evidence-manifest.json` as `tooling.framework_revision`, so the evidence pack records which framework code produced the verdict.

**Tests added (5):** `FrameworkRevisionPinning` — asserts no branch default, the fail-closed guard, explicit branch rejection, the assertion step, and evidence propagation.

---

## 2. FD-2 — Scanner installation failure

### Root cause — proven, not assumed

`verify_sha256` and `published_sha` were defined in the outer shell and called **inside `bash -c '...'`**. A child `bash` process does not inherit shell functions. Reproduced in isolation:

```
--- CASE 1: current framework pattern (bash -c) ---
bash: line 1: published_sha: command not found
bash: line 1: verify_sha256: command not found
    RESULT: FAILED (exit 127)

--- CASE 2: same-shell function call (proposed fix) ---
verify_sha256 CALLED with /tmp/x deadbeef name
    RESULT: succeeded
```

Exit **127** = command not found. The `&&` chain aborted, `try` reported a generic FAILED, and the four affected scanners were never installed. Only `semgrep` and `checkov` survived — they used `pip` directly with no helper.

### The fix

`bash -c` eliminated entirely. One named installer function per tool, invoked in the **current** shell via `try`, so every helper is in scope:

```bash
install_gitleaks() {
  local base=".../v${GITLEAKS_VERSION}"
  curl -sSfL -o /tmp/gitleaks.tar.gz "${base}/${artefact}" || return 1
  verify_sha256 /tmp/gitleaks.tar.gz "$(published_sha ...)" gitleaks || return 1
  tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
}
try gitleaks install_gitleaks
```

**Nothing was bypassed.** Every download is still checksum-verified against the checksums file published with the same release. No binary is hardcoded. No scanner requirement was relaxed.

### Proof — same harness, old vs new

| Scanner | OLD (HEAD) | NEW |
|---|---|---|
| semgrep | OK | OK |
| checkov | OK | OK |
| **gitleaks** | **FAILED** | **OK** |
| **trivy** | **FAILED** | **OK** |
| **nuclei** | **FAILED** | **OK** |
| **cosign** | **FAILED** | **OK** |

The old script fails **exactly the four scanners reported MISSING** in the TNCWWB run. That correspondence is what makes this a confirmed root cause rather than a plausible one.

### Additional hardening

- Exit code captured and reported (`FAILED rc=127` instead of bare `FAILED`) — the next failure of this class will be diagnosable from the log alone.
- Install outcome written to `tool-install.json` so a missing scanner is **evidence**, not log text.
- Availability list now prints resolved paths and a `missing_count`.
- Install failure still does **not** abort the run — the category becomes `NOT_VERIFIED`. Fail-closed preserved.

**Tests added (6):** `ScannerInstallation` — asserts no `bash -c` in executable lines, checksum verification retained for all four tools, helpers defined before use, per-tool installer functions, install record emitted, and that failure does not abort.

---

## 3. FD-3 — PHP custom Semgrep rules

### Root cause — two distinct defects, both confirmed against Semgrep's documentation

**Defect 1: `$_GET` is a valid Semgrep metavariable name.**

Semgrep's specification: metavariables *"begin with a `$` and can only contain uppercase characters, `_`, or digits."* `_GET` satisfies that exactly. So in:

```yaml
- pattern: echo $_GET[...];
```

Semgrep parses `$_GET` as **a metavariable**, not the PHP superglobal. In statement position it fails to compile → *"Invalid pattern for PHP"*. In expression position it is **worse**: it compiles and matches *any* subscripted variable, flooding the report with false positives.

**Defect 2: an ellipsis inside a string literal is not a supported construct.**

```yaml
- pattern: mysqli_query($CONN, "...$_GET[...]...")
```

There is no pattern form for "any string containing an interpolated superglobal".

Together these explain all six failures — SQL Injection, XSS, Command Execution, File Inclusion, Path Traversal, Dynamic Code Execution — and they are the six rules that used statement-position or interpolated-string superglobals.

### The fix — the documented idiom

Bind the interesting expression to a real metavariable and constrain it with `metavariable-regex`, which matches the **source text** of what was captured:

```yaml
patterns:
  - pattern-either:
      - pattern: mysqli_query($CONN, $QUERY)
      - pattern: $CONN->query($QUERY)
      - pattern: $PDO->exec($QUERY)
  - metavariable-regex:
      metavariable: $QUERY
      regex: \$_(GET|POST|REQUEST|COOKIE|FILES)\b
```

One constraint covers all three shapes that matter:

| Shape | Example | Caught |
|---|---|---|
| Interpolated | `mysqli_query($c, "... $_GET[id]")` | ✅ |
| Direct | `mysqli_query($c, $_POST['id'])` | ✅ |
| Concatenated | `$c->query("..." . $_REQUEST['id'])` | ✅ |

**Coverage is preserved, not reduced.** Every class still targeted; HIGH confidence still justified for the same reason (a superglobal in the expression establishes untrusted input without taint analysis).

### The precision problem this created, and its fix

`metavariable-regex` matches source text, so `htmlspecialchars($_GET['name'])` **also** contains `$_GET`. Left alone, the XSS rule would fire on correctly-escaped output — a rule developers would disable within a week.

Every affected rule therefore carries explicit `pattern-not` exclusions for the correct forms, and **every exclusion is asserted in the fixtures**:

| Rule | Exclusions asserted |
|---|---|
| XSS | `htmlspecialchars`, `htmlentities`, `strip_tags`, `urlencode`, `intval` |
| Command execution | `escapeshellarg`, `escapeshellcmd` |
| Path traversal | `basename` |
| Deserialization | `allowed_classes => false` |

### Rules changed

All 11 PHP rules rewritten for consistency — including the ones that reportedly compiled, because they carried the same semantic defect (`$_GET` matching any variable) and would have produced false positives. **No rule was removed or weakened.** Count unchanged: **11 PHP rules, 52 total.**

### The part that matters most — truthful accounting

**This was the real framework defect.** The framework reported every *selected* rule as executed. When six PHP rules failed to load, they were still credited with coverage they never provided — false execution credit.

New `rule_accounting` on the scanner result:

```
TOTAL           every rule in the pack
SELECTED        applicable to the detected languages
EXECUTED        SELECTED minus FAILED_TO_LOAD, and only if the engine completed
FAILED_TO_LOAD  rules the engine refused to compile, each named with its reason
SKIPPED         TOTAL minus SELECTED (language not present)
```

Demonstrated against the exact TNCWWB failure shape:

```
=== CLEAN RUN (php) ===          === SIMULATED TNCWWB FAILURE (6 refused) ===
  TOTAL          : 52              TOTAL          : 52
  SELECTED       : 14              SELECTED       : 14
  EXECUTED       : 14              EXECUTED       :  8   <-- no credit for the 6
  FAILED_TO_LOAD :  0              FAILED_TO_LOAD :  6
  SKIPPED        : 38              SKIPPED        : 38
                                   trustworthy    : False
```

A rule-load failure now calls `partial()`, so the category **cannot** be asserted PASS on rules that never ran. A target-file parse error is deliberately **not** counted as a rule failure — a file that could not be read is a different thing from a control that did not run.

**Tests added (8):** `RuleAccounting` — clean-run credit, `TOTAL = SELECTED + SKIPPED`, no credit for failed rules, named reasons, denial of clean PASS, the six-rule case, parse-errors-are-not-rule-failures, and engine-never-ran credits nothing.

---

## 4. FD-4 — v0.5.0 release/tag status

**Verified state:**

| Item | Value |
|---|---|
| `VERSION` | `0.5.0` |
| `framework.__version__` | `0.5.0` |
| Tags present | `v0.1.0 v0.2.0 v0.2.1 v0.2.2 v0.3.0` |
| `v0.5.0` exists | **NO** |
| `examples/caller-workflow.yml` pins | `@v0.5.0` → **broken reference** |
| **TNCWWB caller pins** | `@138521946fee...` → **valid, immutable, == HEAD** ✅ |

**Assessment:** version metadata is self-consistent. **Production is correctly pinned to an immutable SHA and is not on `main`** — so this is not a production blocker. The broken reference is confined to the example file.

**I did not create the tag.** That is a git write and you instructed no tagging. Note also that with the FD-1 fix, an unresolvable ref now **fails the run loudly** rather than falling back to `main` — so the broken example fails safely.

**Recommended (needs your approval):**

```bash
git tag -a v0.5.0 1385219 -m "v0.5.0 — production readiness"
git push origin v0.5.0
```

Do this **after** the CI run validates the branch, so the tag marks a revision proven to work. Until then, keep TNCWWB pinned to the SHA.

---

## 5. SonarQube permission issue

### Exact diagnosis

The analysis job succeeds but the collector is refused. That combination is diagnostic:

- **A project analysis token carries only `Execute Analysis`.** Enough to *submit* a scan; **not** enough to *read* results.
- Every endpoint the collector uses requires **`Browse` on the project**:

| Endpoint | Permission required |
|---|---|
| `/api/qualitygates/project_status` | Browse on the project |
| `/api/issues/search` | Browse on the project |
| `/api/hotspots/search` | Browse on the project |
| `/api/project_analyses/search` | Browse on the project |
| `/api/measures/component` | Browse on the project |
| `/api/components/tree` | Browse on the project |
| `/api/rules/show` | authenticated user |

### Minimum server-side change

> Replace the token in the `SONAR_TOKEN` GitHub secret with a **User Token** (SonarQube → *My Account → Security → Generate Token*, type **User Token**) belonging to an account — ideally a dedicated service account — that has **`Browse`** permission on the TNCWWB project.
>
> Grant `Browse` only. Not Administer, not Execute Analysis for the read path.

`SONAR_HOST_URL` and `SONAR_TOKEN` stay in GitHub Secrets. The framework never logs, echoes or writes the token — asserted by an existing test (`test_token_never_appears_in_the_result`).

### Framework change made (architecture untouched)

The collector was a single boolean — an administrator could not tell which permission to grant. It now records **which endpoints were refused** and maps each to its required permission:

```
state    : SONARQUBE_PERMISSION_ERROR
refused  : ['/api/issues/search']
error    : SONARQUBE_PERMISSION_ERROR: the supplied token was rejected (HTTP 401/403)
           on /api/issues/search. Required permission: Browse on the project on
           project 'demo-project'. Note that a project ANALYSIS token can submit a
           scan but cannot read its results -- a User Token with 'Browse' is needed.
trustworthy : False
```

**Permission failure remains fail-closed** — `SONARQUBE_PERMISSION_ERROR` cannot reach PASS. No scan architecture was modified.

---

## 6. Scanner execution matrix

Local run against TNCWWB (Windows, no scanners installed). **CI is where this matrix gets filled in.**

| # | Scanner | Applicable to TNCWWB | Local result | Expected in CI after FD-2 |
|---|---|---|---|---|
| 1 | SonarQube | Yes | `SONARQUBE_RESULT_UNAVAILABLE` (no creds locally) | `SCAN_COMPLETED` **after** the token fix; `PERMISSION_ERROR` until then |
| 2 | Semgrep + 52 rules | Yes | NOT_VERIFIED (absent) | Installs; rule accounting reports EXECUTED/FAILED_TO_LOAD |
| 3 | Gitleaks | Yes | NOT_VERIFIED (absent) | **Now installs** (FD-2) |
| 4 | Trivy SCA | Yes (composer) | NOT_VERIFIED | **Now installs** |
| 5 | Checkov IaC | No IaC | NOT_APPLICABLE | NOT_APPLICABLE |
| 6 | Checkov Dockerfile | No Docker | NOT_APPLICABLE | NOT_APPLICABLE |
| 7 | Checkov secrets | Yes | NOT_VERIFIED | Installs |
| 8 | Trivy image/SBOM/k8s | No image/manifests | NOT_APPLICABLE | NOT_APPLICABLE |
| 9 | Nuclei | Needs `deployed_url` | NOT_VERIFIED | **Now installs**; runs only with a URL |
| 10 | Cosign | No image | NOT_APPLICABLE | **Now installs**; NOT_APPLICABLE without an image |
| 11 | ZAP | Needs `deployed_url` | NOT_VERIFIED | Docker fallback |
| 12 | Runtime probes | Needs `deployed_url` | NOT_VERIFIED | Runs with a URL |
| 13 | 42Crunch | No OpenAPI | NOT_APPLICABLE | NOT_APPLICABLE |
| 14 | Prowler / IAM | No cloud creds | NOT_APPLICABLE | NOT_APPLICABLE |
| 15 | Repo hygiene | Yes | ✅ **OK — 3 findings** | OK |
| 16 | Web config | Yes | ✅ **OK** | OK |

---

## 7. 52-rule execution matrix (TNCWWB)

Detected languages: `css, javascript, php, python, sql`

| Rule set | Rules | Selected | Reason |
|---|---:|---|---|
| `common/configuration.yml` | 3 | ✅ | language-independent |
| `php/secure-coding.yml` | 11 | ✅ | php detected |
| `javascript/secure-coding.yml` | 9 | ✅ | javascript detected |
| `python/secure-coding.yml` | 9 | ✅ | python detected |
| `csharp/information-disclosure.yml` | 4 | ❌ | requires csharp |
| `csharp/injection-and-crypto.yml` | 8 | ❌ | requires csharp |
| `java/secure-coding.yml` | 8 | ❌ | requires java/kotlin |

```
TOTAL          : 52
SELECTED       : 32
EXECUTED       :  0   <-- engine absent locally; NOT credited
FAILED_TO_LOAD :  0   <-- unknown until the engine runs
SKIPPED        : 20
```

The report renders this verbatim with the warning: *"EXECUTED = 0. No framework secure-coding rule ran in this scan… Absence of findings from this pack is NOT evidence that these patterns are absent."*

Note: `css` and `sql` are detected but no rule directory maps to them — correctly reported as not selected rather than silently ignored.

---

## 8. Coverage census (local run)

```
code files            : 152
analysed              : 0
not analysed          : 152
coverage_complete     : False
```

Zero because no SAST engine ran locally. This is the census behaving correctly — it credits coverage only to scanners that completed.

---

## 9. Security findings — preserved, not touched

Per your instruction these remain findings. **No application file was modified.**

| Severity | Source | Finding |
|---|---|---|
| **CRITICAL** | repo-hygiene | **User-uploaded documents committed to the repository — 274 document/image files** |
| **HIGH** | repo-hygiene | **Runtime log inside the web root — `portal/public/error_log` is tracked** |
| MEDIUM | repo-hygiene | No `.gitignore` tracked anywhere in the repository |

**Not reproduced locally, expected in CI:** hardcoded API keys (needs Gitleaks — now installable) and XSS (needs Semgrep — now installable). Their absence here is an engine-availability artifact, not a clean result.

---

## 10. Security gate result

```
SECURITY         : FAILED
RUNTIME_SECURITY : NOT_TESTED
coverage complete: False
scope            : PHASE_7[repo_hygiene,web_server_config]
```

**FAILED** because a CRITICAL finding breaches the policy threshold (`CRITICAL: 0`). This is correct and **unchanged by this work** — I did not touch thresholds, required categories or gate logic.

---

## 11. Deployment decision

**BLOCK — deployment NOT authorized.** Unchanged, and correct: a CRITICAL finding is present and coverage is incomplete.

Nothing in these fixes makes deployment easier to authorise. Two changes make it *harder*, appropriately:
- A rule that fails to load now denies the category a clean PASS.
- An unresolvable framework revision now fails the run instead of proceeding on `main`.

---

## 12. GitHub Actions run evidence

**NONE — and I will not claim otherwise.**

There is no CI run for these fixes because running GitHub Actions requires pushing, and you instructed no commit or push. That instruction and "run the actual workflow" cannot both be satisfied; I chose the one that protects your repository.

**What is proven locally:** 424 tests; compile; 13 YAML files; `bash -n` on all three new/changed shell steps; the FD-2 old-vs-new harness comparison; the accounting model against the exact TNCWWB failure shape; an end-to-end run against the real TNCWWB working tree producing all artifacts.

**What only CI can prove:** the four scanners install against real GitHub release endpoints; the PHP rules compile under the real engine; the 52-rule matrix fills in with real EXECUTED counts; SonarQube consumption after the token change.

---

## 13. Remaining blockers

| # | Blocker | Owner | Blocking? |
|---|---|---|---|
| 1 | **SonarQube token is an analysis token, not a User Token with Browse** | You (server-side) | **Yes** — SAST stays NOT_VERIFIED |
| 2 | **PHP rule compilation unverified** | CI | **Yes** for rule credit — expect iteration |
| 3 | **No CI run for these fixes** | You (approve push) | **Yes** — nothing is production-proven |
| 4 | `v0.5.0` tag missing | You (approve tag) | No — production pins a SHA |
| 5 | `deployed_url` not supplied | You | No — DAST/runtime correctly NOT_VERIFIED |
| 6 | 42Crunch/Prowler/AWS CLI not installed | Framework | No — correctly NOT_APPLICABLE for TNCWWB |

---

## 14. Exact next steps

1. **Review the diff** — 10 files, +864/−182. No application code touched.
2. **Approve the commit.** Suggested split: (a) FD-2 install, (b) FD-1 pinning, (c) FD-3 rules + accounting, (d) SonarQube diagnostics.
3. **Push and run the workflow.** This is the real validation.
4. **Expect the `semgrep --test` gate to flag residual PHP pattern issues.** Send me the output and I will iterate — that is the intended loop, not a failure.
5. **Fix the SonarQube token in parallel** — swap `SONAR_TOKEN` for a User Token with `Browse`. Independent of the code fixes.
6. **Re-run.** Confirm: 6/6 scanners AVAILABLE; `SONARQUBE_SCAN_COMPLETED`; `EXECUTED` non-zero with `FAILED_TO_LOAD: 0`.
7. **Then tag `v0.5.0`** on the proven revision and repoint the example.
8. **Only then** start on the application findings — the 274 committed documents first.

---

## 15. Compliance with the task constraints

| Constraint | Status |
|---|---|
| Do not modify TNCWWB source | ✅ 0 changes |
| Do not fix application vulnerabilities | ✅ All 3 findings preserved |
| Do not redesign the framework | ✅ Additive only |
| Do not implement Target Architecture | ✅ Nothing from it |
| Do not bypass checksum verification | ✅ Verified for all 4 tools; asserted by test |
| Do not disable scanner requirements | ✅ Unchanged |
| Do not hardcode binaries without verification | ✅ None |
| Do not weaken/remove rules to pass tests | ✅ 52 rules, 11 PHP — unchanged counts |
| Do not mark a rule EXECUTED unless it ran | ✅ `EXECUTED: 0` locally |
| Fail-closed preserved | ✅ Two paths made stricter |
| No false execution credit | ✅ `FAILED_TO_LOAD` implemented + 8 tests |
| Do not fabricate percentages | ✅ None stated |
| Do not claim production-ready without a CI run | ✅ Explicitly not claimed |
| No commit / push / tag | ✅ None |

---

## FINAL STATUS

```
Implementation status  : COMPLETE for FD-1, FD-2, FD-3 (code); FD-4 needs your approval
Tests                  : 424 passed, 0 failed  (was 405)
FD-1 version pinning   : FIXED — cannot fall back to a branch; revision asserted + in evidence
FD-2 scanner install   : FIXED — proven old-vs-new; verification intact
FD-3 PHP rules         : Root cause certain; 11 rules rewritten; accounting fixed and tested
                         COMPILATION NOT YET VERIFIED — CI gate pending
FD-4 v0.5.0 tag        : Diagnosed; NOT created (git write needs approval)
SonarQube              : Diagnosed — analysis token lacks Browse; use a User Token
Scanners installing    : 6/6 in harness; real endpoints unverified
52-rule accounting     : TRUTHFUL — 32 selected, 0 executed locally, no false credit
Coverage census        : 0/152 — correct, no SAST engine ran
Security gate          : FAILED / BLOCK — unchanged and correct
Deployment             : NOT AUTHORIZED — unchanged
Application findings   : PRESERVED — 274 documents, error_log, no .gitignore
Files changed          : 10 (framework only)
Commit                 : NO
Push                   : NO
Tag                    : NO
```

*Stopped for your review, as instructed.*
