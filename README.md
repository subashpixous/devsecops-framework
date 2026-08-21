# Universal Production DevSecOps Security Validation Framework

A reusable security validation layer for production repositories. It wraps an
existing delivery pipeline instead of replacing it: it does not build, does not
deploy, and does not modify the project it inspects.

**Current release: v0.1.0 — Phase 1 (SonarQube collection, normalisation, status
engine, JSON/Markdown/PDF reporting).**

---

## What it guarantees

| Guarantee | How |
|---|---|
| No false PASS | Every failure path resolves to `NOT_VERIFIED`. Enforced by unit tests that must pass before a release tag is cut. |
| No silent gaps | Every security category resolves to exactly one of `PASS` / `FAILED` / `NOT_VERIFIED` / `NOT_APPLICABLE` / `NOT_IMPLEMENTED` and is printed in every report. |
| Status independence | `BUILD`, `DEPLOYMENT`, `SECURITY` and `RUNTIME_SECURITY` are computed separately. A successful deployment can never raise a security status. |
| Honest coverage | Reports state which categories were not tested and why, and list the 11 manual control areas no scanner can cover. |
| Read-only | The SonarQube collector issues `GET` only. CI asserts that no mutating HTTP verb exists in any collector. |
| Project-agnostic | No repository name, no per-project branch. CI asserts no project identifier appears in the framework. |

## Architecture

```
Project  ->  Detection  ->  Capabilities  ->  Applicable Controls  ->  Scanners
                                                                          |
                        Findings (one common schema, every tool)  <-------+
                                     |
                              Status Engine
                                     |
              BUILD / DEPLOYMENT / SECURITY / RUNTIME_SECURITY
                                     |
                  final-report.json -> report.md -> security-report.pdf
```

## Usage

Add one file to the project — see [examples/caller-workflow.yml](examples/caller-workflow.yml):

```yaml
jobs:
  security:
    uses: <owner>/devsecops-framework/.github/workflows/security-pipeline.yml@<sha>
    with:
      environment: production
    secrets:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

## Local use

```bash
pip install -r requirements.txt

# What does the framework see in this repository?
python -m framework.cli detect --workspace /path/to/project

# Full pipeline against a live SonarQube server
export SONAR_HOST_URL=https://sonar.example.com
export SONAR_TOKEN=<token>
python -m framework.cli run --workspace /path/to/project --output security-results
```

Exit codes: `0` reports generated · `2` SECURITY=FAILED (with `--fail-on-security`)
· `3` SECURITY=NOT_VERIFIED (with `--fail-on-security`) · `4` the framework itself failed.
Exit `4` exists so a broken framework is loud; it never becomes a passing verdict.

## Artifacts

```
security-results/
├── capabilities.json          what was detected, with evidence
├── sonarqube.json             raw collector payload (evidence)
├── normalized-findings.json   common finding schema
├── final-report.json          machine-readable source of truth
├── report.md
└── security-report.pdf
```

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 1 | SonarQube collector, normaliser, status engine, reporting | **shipped** |
| 2 | Gitleaks, Trivy SCA, Semgrep/OpenGrep, Checkov | planned |
| 3 | Trivy image, SBOM, frontend bundle scanner, cosign | planned |
| 4 | Finding lifecycle, exceptions, accepted-risk expiry | planned |
| 5 | OWASP ZAP, Nuclei, runtime probes, 42Crunch | planned |
| 6 | Prowler, IAM Access Analyzer, DefectDojo, manual-control tracking | planned |

Every planned category already appears in `framework/core/categories.py` and is
reported as `NOT_IMPLEMENTED` today. Shipping a phase means changing its `phase`
value and registering a collector — no redesign.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/ONBOARDING.md](docs/ONBOARDING.md) and
[docs/ADDING-A-SCANNER.md](docs/ADDING-A-SCANNER.md).

## What this framework does not do

Automation cannot detect IDOR/BOLA, authorization or authentication bypass,
account takeover, privilege escalation, business logic flaws, race conditions,
payment manipulation, complex attack chains, advanced SSRF/deserialization, or
zero-day threats. These are declared permanently in
`framework/core/manual_controls.py` and printed in every report as
`MANUAL_NOT_TESTED`. A report from this framework is never a complete security
assessment.
