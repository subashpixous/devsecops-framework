# Onboarding a project

Works the same for Flutter, React, Angular, Node, .NET, Java, Python, PHP and any
other stack, on AWS, EC2, ECS, Kubernetes, Windows/IIS, cPanel, VPS or bare Linux.
Nothing below is stack-specific, because detection handles the differences.

## 1. Check what the framework sees

Before adding any workflow, run detection locally. It writes nothing to the
project and makes no network calls.

```bash
python -m framework.cli detect --workspace /path/to/project
```

Read `capabilities.json`. Confirm that `languages`, `docker`, `iac`,
`kubernetes`, `openapi`, `frontend` and `backend` match reality. Anything the
detector could not establish is empty, and empty means the report will print
`NOT_ESTABLISHED` — that is correct behaviour, not a defect to work around.

## 2. Confirm the analysis server prerequisites

The project needs an existing SonarQube project key, resolvable from one of:

- `sonar-project.properties` (`sonar.projectKey=...`)
- `SONAR_PROJECT_KEY` environment variable
- `pom.xml`, `gradle.properties`, or a `.csproj` Sonar property
- the `sonar_project_key` workflow input

If none resolves, the collector fails and `SECURITY` becomes `NOT_VERIFIED`. It
does not guess.

The repository needs two existing secrets — `SONAR_TOKEN` and `SONAR_HOST_URL`.
The framework reuses them read-only and never rotates, logs or echoes them.

## 3. Add the caller workflow

Copy [`examples/caller-workflow.yml`](../examples/caller-workflow.yml) to
`.github/workflows/security.yml` and set `environment`. Leave
`deployment_target` and `deployed_url` empty unless they are actually known.

Keep `workflow_dispatch` as the only trigger for the first run.

## 4. Validate before enabling automatic triggers

1. Run the workflow manually from the Actions tab.
2. Download the `security-results` artifact.
3. Check in `final-report.json`:
   - `scanners[].status` is `OK` — anything else means the run did not verify anything;
   - `status.security` is a real verdict rather than `NOT_VERIFIED`;
   - `capabilities` matches the project;
   - `limitations` — in particular `SAST_LANGUAGE_COVERAGE_UNCONFIRMED`, which
     means a language present in the repository produced no findings and may not
     be analysed at all.
4. Only then enable `push` / `pull_request` triggers.

## 5. Optional policy override

Commit a policy file to the project and point `policy_path` at it. It is
deep-merged over the framework default, so omitting a key inherits the default
rather than disabling it.

```yaml
# security-policy.yml
severity_thresholds:
  CRITICAL: 0
  HIGH: 0
  MEDIUM: 25
hotspots_count_toward_thresholds: true
```

## What Phase 1 deliberately does not do

- It does not modify the project's build or deploy workflow.
- It does not block deployment. `fail_on_security` defaults to `false`.
- It does not fix findings. Application code is never changed by the framework.
- It does not cover SCA, secrets, container, IaC, DAST or cloud posture yet.
  Those categories are reported as `NOT_IMPLEMENTED`, not omitted.
