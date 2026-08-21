# Adding a scanner

The engine, the schema and the reports never change when a scanner is added.
This is the whole contract.

## 1. The category already exists

Every future control is already declared in `framework/core/categories.py` and is
already being reported as `NOT_IMPLEMENTED`. Find its key — for example
`secret_scanning`, `sca_dependencies`, `container_image`, `dast_zap`.

If you genuinely need a new category, add it there with its `phase`,
`applies_when` rule and `tools`. Never add a category anywhere else.

## 2. Write the collector

```python
# framework/collectors/gitleaks.py
from ..core.registry import ScannerRegistration, register_scanner
from .base import Collector, ScannerResult

class GitleaksCollector(Collector):
    tool = "gitleaks"
    category_key = "secret_scanning"

    def collect(self) -> ScannerResult:
        result = self.new_result()
        try:
            ...                       # run the tool, parse its output
            result.payload = {...}    # raw evidence, written to security-results/
            result.succeed()
        except Exception as exc:
            result.fail("gitleaks did not complete: %s" % exc)
        return result.finish()
```

Rules:

- **Never raise past `collect()`.** Return a failed `ScannerResult` instead. The
  status engine turns that into `NOT_VERIFIED`.
- **Never return an empty payload on failure.** An empty finding list from a
  broken scanner would look identical to a clean scan. Call `result.fail(...)`.
- Use `result.partial(...)` when the scan ran but is incomplete — truncated
  results, an unavailable sub-endpoint, a skipped path.
- Never log, echo or persist a credential.

## 3. Write the adapter

```python
# framework/adapters/gitleaks_adapter.py
from ..core.schema import Finding
from .base import Adapter

class GitleaksAdapter(Adapter):
    tool = "gitleaks"
    category_key = "secret_scanning"

    def normalize(self, result, context):
        findings = []
        for item in (result.payload or {}).get("findings", []):
            findings.append(self.stamp(Finding(
                tool="gitleaks",
                category="secret",            # policy vocabulary, see below
                severity="CRITICAL",
                file=item["file"],
                line=item["line"],
                evidence="rule=%s" % item["rule"],   # NEVER the secret value
                description=item["description"],
                impact="...",
                remediation="...",
                rule=item["rule"],
                scanner_category="secret_scanning",
            ), context))
        return findings
```

`category` is the *class* of finding and is what policy evaluates. Existing
values: `vulnerability`, `security_hotspot`, `bug`, `code_smell`. Suggested
additions: `secret`, `dependency_vulnerability`, `misconfiguration`,
`dast_finding`, `license`. Add new security-relevant values to
`security_finding_categories` in the policy, otherwise they are collected and
reported but do not affect the verdict.

`scanner_category` is the framework category key and must match the collector's.

**Never put a secret value, token, password or connection string into
`evidence`.** Artifacts are downloadable. Reference file, line and rule only.

## 4. Register it

```python
register_scanner(ScannerRegistration(
    tool="gitleaks",
    category_key="secret_scanning",
    collector_factory=_build_collector,   # must ignore kwargs it does not use
    adapter_factory=_build_adapter,
    description="Committed credential detection.",
))
```

Then import it from `load_builtin_scanners()` in `framework/core/registry.py`.

Collector factories receive a shared kwarg bag (`workspace`, `branch`,
`project_key`, ...). Filter it, as `sonarqube.py` does with `_COLLECTOR_KWARGS`,
so adding a kwarg for one tool never breaks another.

## 5. Move the phase

Change the category's `phase` to the active phase, and bump `active_phase` in
`framework/policy/default-policy.yml`. Decide deliberately whether the new
category belongs in `required_categories`: a required category that fails to run
turns the whole verdict into `NOT_VERIFIED`.

## 6. Add invariant tests

At minimum, mirror the existing suite for the new tool:

- collector failure → category `NOT_VERIFIED`, never `PASS`
- empty payload → result marked failed, not "clean"
- findings above threshold → `FAILED`
- deployment status has no effect on the outcome

`tests/test_status_engine.py` must keep passing unchanged — if adding a scanner
breaks an invariant test, the invariant is right and the scanner is wrong.
