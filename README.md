# Universal Production DevSecOps Security Validation Framework

A reusable security validation layer for production repositories. It wraps an
existing delivery pipeline instead of replacing it: it does not build, does not
deploy, and does not modify the project it inspects.

**Current release: v0.6.0 — deployment readiness assessment, an explicit deployment decision, and a pipeline that no longer stops at the first finding.**

> A security finding does not fail this pipeline. The run completes, publishes every
> finding, computes deployment readiness from real evidence and uploads the evidence
> pack. Gate your deployment job on the `deployment_decision` output. Nothing is
> suppressed, downgraded or hidden to achieve that — see the guarantees below.

---

## What it guarantees

| Guarantee | How |
|---|---|
| No false PASS | Every failure path resolves to `NOT_VERIFIED`. A missing tool, a failed scan, a partial result, a skipped input and a malformed payload are all non-PASS. Enforced by unit tests that must pass before a release tag is cut. |
| No unread code | Every file lands in one coverage bucket with a reason: analysed, excluded (pattern named), no engine for its type, or its engine did not complete. A scanner that failed is credited with nothing. |
| Per-scanner proof | Every scanner reports its own reach — files analysed, excluded, outside its file types, and not analysed because it did not run. A scanner with no declared file reach reports `n/a`, never `0`, so no gap is invented. |
| No stale analysis | SonarQube results are compared against the commit under validation. `SONARQUBE_RESULT_STALE`, `_UNAVAILABLE` and `_PERMISSION_ERROR` can never reach PASS. |
| No fabricated risk data | A CVE with no EPSS score gets no score — never `0.0`, which would sort as harmless. Unreachable sources report `EPSS_UNAVAILABLE` / `KEV_UNAVAILABLE`, and never influence the verdict. |
| Corroboration is kept | When two scanners find the same defect, both findings are retained and the report says `Detected by: sonarqube + semgrep`. Merging would lose evidence and let one exception suppress two sources. |
| Reproducible runs | `evidence-manifest.json` records commit, versions, policy, per-scanner exit codes, coverage and a SHA-256 of every artefact. It states plainly that digests are not signatures. |
| No silent gaps | All 20 security categories resolve to exactly one of `PASS` / `FAILED` / `NOT_VERIFIED` / `NOT_APPLICABLE` / `NOT_IMPLEMENTED` and appear in every report. |
| Status independence | `PIPELINE`, `BUILD`, `DEPLOYMENT`, `SECURITY`, `RUNTIME_SECURITY`, `EVIDENCE` and the `DEPLOYMENT DECISION` are computed separately. A successful deployment can never raise a security status, and a security finding never terminates the run. |
| Findings never stop the run | A finding lowers readiness and appears as a condition or a blocker. It never exits non-zero on its own, because doing so skips the stages that publish it. A *self-contradictory evidence set* still stops the run. |
| An unknown is never a pass | A readiness dimension that was not measured earns nothing AND is not dropped: its weight moves to the assurance denominator. No arrangement of `NOT_TESTED` / `NOT_VERIFIED` / `NOT_REPORTED` can produce a high assurance figure. |
| Every percentage is recomputable | Each readiness dimension publishes its state, weight, score and evidence; the report publishes the formula and the sums. No figure is assigned, estimated or carried over. |
| No secrets in output | Gitleaks' `Secret`/`Match` fields are stripped at collection; bundle findings carry a length and a SHA-256 prefix, never the value; tool output is redacted; ZAP and Nuclei response echoes are dropped. |
| Suppressions cannot rot | An exception with no expiry date, or a past one, is EXPIRED and does **not** suppress. |
| A broken scanner is never remediation | A finding only becomes `FIXED` when the scanner that originally found it ran successfully in this run. |
| Read-only where it matters | SonarQube, runtime probes and IAM Access Analyzer issue GET/list calls only. cosign verifies and never signs. CI asserts no mutating verb exists. |
| Project-agnostic | No repository name, no per-project branch. CI asserts no project identifier appears in the framework. |

## The pipeline

```
Developer Push / PR
        │
   Project Detection ─────────────► capabilities.json
        │
   PRE-BUILD      SonarQube · Semgrep/OpenGrep · Gitleaks · Trivy SCA
                  Checkov (IaC) · 42Crunch (OpenAPI)
        │
      BUILD       (your existing build — untouched)
        │
   POST-BUILD     Trivy image · Trivy SBOM · Frontend bundle scanner
                  cosign/Sigstore · Trivy Kubernetes
        │
   DEPLOYMENT     (your existing deployment — untouched)
        │
   POST-DEPLOY    OWASP ZAP · Nuclei · Runtime probes
                  (TLS, headers, cookies, CORS, debug surfaces,
                   error disclosure, live JS bundle validation)
        │
      CLOUD       Prowler · IAM Access Analyzer
        │
  AGGREGATION     normalize → fingerprint → new / existing / fixed /
                  false-positive / accepted-risk / expired / unknown
        │
    READINESS     one dimension per applicable category, plus build, tests,
                  test coverage, file coverage, scanner execution, evidence
                  integrity and outstanding risk
        │
   SIX RESULTS    PIPELINE · SECURITY · EVIDENCE · READINESS % · ASSURANCE %
                  · DEPLOYMENT DECISION   (none derived from another)
        │
     REPORTS      final-report.json · report.md · security-report.pdf
                  · findings.csv · security.sarif · evidence-manifest.json
                  → GitHub Actions artifact
```

## The deployment decision

`READY` · `CONDITIONALLY_READY` · `NOT_READY` · `UNKNOWN` — computed from evidence,
published as a workflow output, and independent of the CI exit status.

```
readiness = 100 x sum(score x weight for MEASURED dimensions)
                / sum(weight     for MEASURED dimensions)
assurance = 100 x sum(weight MEASURED)
                / (sum(weight MEASURED) + sum(weight UNKNOWN))
```

Read the two together. `readiness 100% / assurance 20%` means one thing was
checked and it passed — which is why `assurance` gates the decision as hard as
`readiness` does.

| State | Effect on the calculation |
|---|---|
| `PASS` / `FAILED` / `PARTIAL` | Measured. Scores 1.0 / 0.0 / a fraction. |
| `NOT_APPLICABLE` | Leaves **both** sums. No Dockerfile is not a gap. |
| `NOT_VERIFIED` / `NOT_TESTED` / `NOT_REPORTED` | Earns nothing, and its weight moves to the assurance denominator. Never a pass. |

Only a `CRITICAL` finding blocks on its own. A `HIGH` finding lowers the score
and is listed as an outstanding condition — visible and costly, but it does not
terminate anything. Accepting risk is done in the exceptions file, with an owner
and an expiry date; there is no other mechanism.

Weights, risk points and thresholds are **data** in `framework/policy/default-policy.yml`
and can be overridden per project. They are printed in every report next to the
figure they produced.

Stages run independently, so each can be wired to the point in your pipeline
where its inputs actually exist.

## Scanners

| Category | Tool | Stage | Needs |
|---|---|---|---|
| Static analysis | SonarQube | PRE_BUILD | `SONAR_TOKEN`, `SONAR_HOST_URL` |
| Static analysis | Semgrep / OpenGrep | PRE_BUILD | binary |
| Secret scanning | Gitleaks | PRE_BUILD | binary |
| Dependency / SCA | Trivy | PRE_BUILD | binary |
| Infrastructure as code | Checkov | PRE_BUILD | binary, IaC present |
| API specification | 42Crunch | PRE_BUILD | `FORTYTWO_CRUNCH_TOKEN`, spec file |
| Repository hygiene & data exposure | framework-native | PRE_BUILD | git |
| Web server configuration | framework-native | PRE_BUILD | committed `.htaccess`/nginx conf |
| Container image | Trivy | POST_BUILD | binary, `images` input |
| SBOM | Trivy (CycloneDX) | POST_BUILD | binary |
| Frontend bundle secrets | framework-native | POST_BUILD | built output |
| Artifact signing | cosign / Sigstore | POST_BUILD | binary, verification key |
| Kubernetes workloads | Trivy config | POST_BUILD | binary, manifests |
| Finding lifecycle | framework-native | AGGREGATION | baseline (optional) |
| DAST | OWASP ZAP | POST_DEPLOY | binary or docker, `deployed_url` |
| Known exposures | Nuclei | POST_DEPLOY | binary, `deployed_url` |
| Runtime probes | framework-native | POST_DEPLOY | `deployed_url` |
| Cloud posture | Prowler | CLOUD | binary, cloud credentials |
| IAM external access | AWS Access Analyzer | CLOUD | AWS CLI + credentials |

Anything a project does not have is `NOT_APPLICABLE` and says so. Anything that
could not run is `NOT_VERIFIED` and says why.

## Usage

Add one file to the project — see [examples/caller-workflow.yml](examples/caller-workflow.yml):

```yaml
permissions:
  contents: read
  security-events: write   # so findings land in the PR, not only in an artifact

jobs:
  security:
    uses: <owner>/devsecops-framework/.github/workflows/security-pipeline.yml@<sha>
    with:
      environment: production
      stages: PRE_BUILD
    secrets:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

## Local use

```bash
pip install -r requirements.txt

python -m framework.cli tools                     # what is installed?
python -m framework.cli detect --workspace /path  # what does it see?
python -m framework.cli run --workspace /path --output security-results
```

Useful flags: `--stage PRE_BUILD,POST_BUILD` · `--images org/app:sha` ·
`--deployed-url https://app.example.com` · `--baseline prev/normalized-findings.json` ·
`--exceptions .security/exceptions.yml` · `--fail-on never|evidence|decision|security` ·
`--test-status pass` · `--test-coverage-percent 84.2` ·
`--include-dependencies` · `--max-detailed-findings 500`

Exit codes: `0` reports generated — **the default, whatever was found** · `2`
SECURITY=FAILED · `3` SECURITY=NOT_VERIFIED · `5` the deployment decision is not
READY · `6` the evidence set contradicts itself · `4` the framework itself failed.
Codes `2`, `3`, `5` and `6` require the matching `--fail-on` selector; `4` is
unconditional so a broken framework is loud, and it never becomes a passing verdict.

## Artifacts

```
security-results/
├── capabilities.json          what was detected, with evidence
├── <tool>.json                raw payload per scanner (written when one exists)
├── sbom.cdx.json              CycloneDX SBOM, when generated
├── normalized-findings.json   common schema — also the next run's baseline
├── final-report.json          machine-readable source of truth
├── evidence-manifest.json     provenance: commit, versions, policy, exit codes,
│                              coverage, verdict, SHA-256 of every artefact
├── findings.csv               EVERY finding, never truncated, with an owner column
├── security.sarif             uploaded to code scanning — inline in the PR
├── report.md
└── security-report.pdf
```

## Exploitability enrichment

Findings carrying a CVE are enriched with [EPSS](https://www.first.org/epss/)
exploit probability and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
known-exploited status, so a list of CRITICALs becomes an ordering.

Both are third-party network calls, so both degrade rather than fail:

| Flag | Effect |
|---|---|
| *(default)* | Live lookup; failure reports `EPSS_UNAVAILABLE` / `KEV_UNAVAILABLE` |
| `--no-enrichment` | Skip both entirely; reports `EPSS_DISABLED` / `KEV_DISABLED` |
| `--epss-file` / `--kev-file` | Read from local JSON — air-gapped runners |

Enrichment **never influences the security verdict.** It orders findings; the
policy decides them. A verdict that depended on a third-party API would change
during that API's outage.

## Coverage

Covers, where automation can: secrets and API keys, SQL injection, XSS, SSRF,
command injection, path traversal, file upload, sensitive data exposure,
internal infrastructure leakage, stack traces, JWT/session weaknesses,
dependency and container CVEs, IaC and cloud misconfiguration, CORS, TLS,
security headers, cookie security, supply-chain/provenance, and API contract
security.

**It does not claim complete detection.** Where automation cannot decide,
the report emits an `AUTOMATION LIMITATION` naming the required follow-up:
manual security review, threat modeling, authenticated testing, penetration
testing, runtime monitoring or cloud security review.

Eleven control areas are declared permanently non-automatable in
`framework/core/manual_controls.py` and print as `MANUAL_NOT_TESTED` in every
report: IDOR/BOLA, authorization bypass, authentication bypass, account
takeover, privilege escalation, business logic, race conditions, payment
manipulation, complex attack chains, advanced SSRF/deserialization, and
zero-day threats.

## Roadmap status

| Phase | Scope | State |
|---|---|---|
| 1 | SonarQube collector, normaliser, status engine, reporting | **shipped** |
| 2 | Gitleaks, Trivy SCA, Semgrep/OpenGrep, Checkov | **shipped** |
| 3 | Trivy image, SBOM, frontend bundle scanner, cosign | **shipped** |
| 4 | Finding lifecycle, exceptions, accepted-risk expiry | **shipped** |
| 5 | OWASP ZAP, Nuclei, runtime probes, 42Crunch | **shipped** |
| 6 | Prowler, IAM Access Analyzer | **shipped** |
| 7 | Repository hygiene, web server config, file-level coverage, SARIF | **shipped** |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ONBOARDING.md](docs/ONBOARDING.md) and
[docs/ADDING-A-SCANNER.md](docs/ADDING-A-SCANNER.md).
