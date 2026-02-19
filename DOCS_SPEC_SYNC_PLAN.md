# Docs/Spec Sync Plan (Docs-Only)

## Goal
Bring project documentation into strict alignment with the currently implemented API/spec behavior, without changing any code or runtime behavior.

## Constraint
- Update docs only.
- Do not modify implementation (`api/`, `internal/`, `cmd/`, scripts logic).

## Source Of Truth (for this sync)
Use implemented behavior as canonical:
- API spec enum/range: `api/v1alpha1/vulnerablelab_types.go`
- Vulnerability application + valid subIssue ranges: `internal/breaker/breaker.go`
- Remediation checks: `internal/breaker/remediate.go`
- Runtime flow and persistence behavior: `internal/controller/vulnerablelab_controller.go`

## Canonical Implemented Scope (Current)
- Supported vulnerability categories: `K01`, `K03`, `K07`, `K08`, and `random`
- Valid subIssue ranges:
  - `K01`: `0-4` (5 sub-issues)
  - `K03`: `0-6` (7 sub-issues)
  - `K07`: `0` (1 sub-issue)
  - `K08`: `0` (1 sub-issue)
- Total implemented sub-issues: `14`

## Known Drift To Resolve
1. `README.md`
- Claims unsupported categories/sub-issue counts (e.g., `K02`, `K06`, and larger counts for K01/K03/K07/K08).
- Scanner/tool mapping includes flows not aligned to implemented scope.
- Some language describes capabilities not present in code.

2. `TESTING-STRATEGY.md`
- Describes a 22-vulnerability matrix including `K02` and `K06`, which are not in current API enum/runtime behavior.
- References scripts/files that do not exist in repo (`scripts/test-operator.sh`, `scripts/verify-remediation-cycle.sh`).

3. `testdata/vulnerability-matrix.yaml`
- Contains `K02`/`K06` and 22-total structure inconsistent with current implemented spec.

4. `examples/README.md`
- Documents categories/sub-issues and files not matching current implementation/files.
- References deleted/nonexistent example manifests.

## Execution Plan

### Phase 1: Freeze Canonical Spec In Docs
1. Add a short "Implemented Scope" section to `README.md` with canonical categories/subIssue ranges.
2. Explicitly label unsupported categories as "not implemented in this version."
3. Align "Sub-categories" list to actual implemented sub-issues and counts.

### Phase 2: Align Usage/Examples Docs
1. Update `examples/README.md` to list only implemented categories/sub-issues.
2. Remove references to nonexistent example files.
3. Keep examples focused on what users can run today.

### Phase 3: Align Testing Docs
1. Rewrite `TESTING-STRATEGY.md` to current implemented scope (`14` sub-issues across `K01/K03/K07/K08`).
2. Remove or clearly mark historical/future sections that mention unsupported categories.
3. Replace references to missing scripts with currently existing scripts, or mark as planned.

### Phase 4: Align Test Matrix Doc Artifact
1. Update `testdata/vulnerability-matrix.yaml` to current implemented categories/subIssue ranges.
2. If future categories are kept for roadmap purposes, move them to a clearly marked `future` section.

### Phase 5: Consistency Pass
1. Cross-check all docs for:
   - category names
   - subIssue ranges/counts
   - scanner mappings
   - file/script references
2. Ensure every referenced file path exists.
3. Ensure every documented command can run as-written in current repo context.

## Acceptance Criteria
- Every category documented is present in API enum and runtime switch logic.
- Every documented subIssue index is valid for that category per implementation.
- Total vulnerability count in docs matches implementation (`14`).
- No docs reference missing files/scripts.
- README, examples, and testing docs all tell the same story.

## Out Of Scope
- Implementing `K02`/`K06` (or any additional categories) in code.
- Changing CRD schema, controller behavior, breaker logic, or remediation logic.
- Adding new runtime automation or CI checks (can be proposed later).

## Suggested Order Of PRs
1. PR-1: `README.md` + `examples/README.md` alignment.
2. PR-2: `TESTING-STRATEGY.md` + `testdata/vulnerability-matrix.yaml` alignment.
3. PR-3: final consistency/sweep pass (terminology, links, commands).

## Post-Sync Guardrail (Documentation Process)
For future updates, require that docs changes touching supported categories/subIssue ranges include a quick checklist against:
- API enum
- breaker subIssue validation ranges
- remediation switch coverage
- existing scripts/examples
