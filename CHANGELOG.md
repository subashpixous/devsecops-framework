# Changelog

All notable changes to this framework are recorded here. Releases are immutable
tags; callers pin a tag or SHA, and rollback means repinning the previous one.

## [0.1.0] — 2026-08-21

Phase 1. First release.

### Added

- **Common finding schema** (`core/schema.py`) — the approved 19-key contract
  emitted verbatim and in order, plus additive framework extensions. Canonical
  severity normalisation across scanner vocabularies; unrecognised severities
  become `UNKNOWN` and fail closed rather than being downgraded to `INFO`.
  Line-independent fingerprints, ready for the Phase 4 lifecycle model.
- **Security category matrix** (`core/categories.py`) — all 17 categories across
  phases 1–6 declared up front, each with a phase and an applicability rule.
  Categories never disappear; they resolve to `NOT_APPLICABLE`,
  `NOT_IMPLEMENTED`, `NOT_VERIFIED`, `FAILED` or `PASS`.
- **Status engine** (`core/status_engine.py`) — four independent statuses:
  `BUILD`, `DEPLOYMENT`, `SECURITY`, `RUNTIME_SECURITY`. Deployment state is not
  an input to the security computation.
- **Read-only SonarQube collector** (`collectors/sonarqube.py`) — quality gate,
  issues, security hotspots, rule metadata. `GET` only; no admin endpoint; no
  writes. Retries with backoff, pagination, branch-parameter fallback for
  Community Build, and universal project-key resolution.
- **SonarQube adapter** (`adapters/sonarqube_adapter.py`) — issues and hotspots
  into the common schema, with CWE/OWASP mapping from rule security standards.
- **Project detector** (`detect/detector.py`) — evidence-based capability
  detection across Node, .NET, Java, Python, PHP, Ruby, Go, Rust, Dart/Flutter,
  Docker, Terraform, CloudFormation, ARM, Kubernetes, Helm and OpenAPI. Values
  that cannot be established stay empty and render as `NOT_ESTABLISHED`.
- **Policy** (`policy/default-policy.yml`) — thresholds and required controls as
  data. Project overrides deep-merge over the default.
- **Manual controls** (`core/manual_controls.py`) — 11 control areas automation
  cannot cover, permanently `MANUAL_NOT_TESTED`.
- **Reporting** — `final-report.json`, `report.md`, `security-report.pdf`. The
  PDF separates the deployment result and the security result into distinct
  framed sections with an explicit statement that one does not imply the other.
- **Reusable workflow** (`.github/workflows/security-pipeline.yml`) — `workflow_call`
  entrypoint, `permissions: contents: read`, framework pinned via
  `github.job_workflow_sha`, inputs passed through the environment to avoid shell
  injection, artifacts uploaded on `always()`.
- **Self-test CI** — 57 invariant tests plus assertions that collectors contain no
  mutating HTTP verb and that no project identifier leaks into the framework.

### Known gaps

- Third-party actions are referenced by version tag, not SHA. See
  `docs/ARCHITECTURE.md` → Supply chain for the pinning procedure.
- Phases 2–6 are not implemented. Their categories report `NOT_IMPLEMENTED`.
