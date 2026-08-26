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

## 6. Wiring the later stages

`PRE_BUILD` needs only source. The other stages need inputs that exist at
specific points in your pipeline, so call the framework again from there:

| Stage | Required input | Where it comes from |
|---|---|---|
| `POST_BUILD` | `images`, optionally `bundle_dirs` | after your build job produces them |
| `POST_DEPLOY` | `deployed_url` | after your deploy job |
| `CLOUD` | cloud credentials | any time; read-only assessment |

Each call is independent and none of them changes how you build or deploy.

`build_status`, `deployment_status`, `test_status` and `test_coverage_percent`
are passed so the report can state them. They never influence the security
verdict. They *are* readiness dimensions: an omitted value is `NOT_REPORTED`,
which scores nothing and lowers the assurance figure. It is never read as a pass.

## Gating deployment

The security job does not fail on findings, and you should not make it. Gate the
**deployment** job on the decision instead:

```yaml
jobs:
  security:
    uses: <owner>/devsecops-framework/.github/workflows/security-pipeline.yml@<sha>
    with:
      fail_on: never          # the default

  deploy:
    needs: security
    if: needs.security.outputs.deployment_permitted == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

Failing the security job instead skips the steps that publish the findings,
upload the evidence and compute readiness -- so the vulnerability that "blocked"
your pipeline ends up harder to see, not easier.

Outputs you can read: `deployment_decision`, `deployment_permitted`,
`readiness_percent`, `readiness_assurance_percent`, `evidence_status`,
`pipeline_status`, `critical_findings`, `high_findings`, plus everything that
existed before.

**Read `readiness_percent` and `readiness_assurance_percent` together.** 100%
readiness at 20% assurance means one thing was checked and it passed.

## 7. Lifecycle: getting NEW / EXISTING / FIXED

Without a baseline every finding is `NEW` and nothing can be `FIXED`. Give the
pipeline a previous `normalized-findings.json`:

```yaml
with:
  baseline_path: .security/baseline-findings.json
  exceptions_path: .security/exceptions.yml
```

Commit the baseline from a known-good run, or restore it from a prior artifact.
Suppressions go in the exceptions file — see
`framework/policy/exceptions.example.yml`. **Every exception needs an `expires`
date.** Without one it is treated as expired and does not suppress.

## What the framework deliberately does not do

- It does not modify the project's build or deploy workflow.
- It does not block deployment. It publishes a decision; your deployment job
  decides what to do with it.
- It does not fix findings. Application code is never changed by the framework.
- It does not guess. Scanners you have not installed, and inputs you have not
  supplied, report `NOT_VERIFIED` with the exact missing requirement named.
- It does not claim complete detection. Eleven manual control areas print as
  `MANUAL_NOT_TESTED` in every report.
