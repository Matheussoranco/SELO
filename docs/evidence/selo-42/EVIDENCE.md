# Evidence Pack

- **Pack ID:** selo-42-05bf5da
- **Template version:** 1.0
- **Generated at (UTC):** 2026-11-25T18:59:18Z
- **Overall status:** CONDITIONAL
- **Task mode:** github
- **Task reference:** Matheussoranco/SELO#42
- **Repository:** Matheussoranco/SELO
- **Branch:** sail/selo-ci
- **Base revision:** e1765cc05a824ab4e75ef6ce949fb957d32760c1
- **Current revision:** 05bf5daeee50607033b81f3bff9c7c6a7a02a09d (workflow change)
- **Working-tree state:** local suite executed on unchanged application and test files in the isolated worktree
- **Producer:** Codex Lead

## 1. Executive result

PR #43 adds the GitHub Actions workflow requested by #42. The documented suite completed locally on Windows with Python 3.12.10. Hosted matrix results and independent approvals are recorded separately on the PR.

## 2. Scope-to-proof map

| Claim ID | Requirement or property | Source | Verification | Evidence IDs | Status |
| -------- | ------------------------ | ------ | ------------ | ------------ | ------ |
| CLM-001 | The documented suite works with the interoperability extra | #42 and README | Local Windows Python 3.12 test run | EVD-001 | PASS |
| CLM-002 | Pull requests and main run the matrix on Windows and Linux | #42 | Hosted run on the PR and later execution on main | EVD-003 | NOT_RUN |
| CLM-003 | Actions have immutable references and checkout does not persist credentials | #42 | Inspection of the workflow diff | EVD-002 | PASS |

## 3. Change inventory

- **Added:** .github/workflows/ci.yml, this evidence record
- **Modified:** No existing files
- **Deleted:** None
- **Config/schema changes:** Adds the GitHub Actions job matrix
- **Externally visible behaviour changes:** GitHub displays test checks on pull requests and pushes to main
- **Intentionally untouched:** Application code, dependency policy and test suite

## 4. Verification bundle

- **Tests run:** Existing unittest suite with the documented interop extra
- **Newly added tests:** None
- **Edge/failure cases covered:** Existing cryptography, interoperability and loopback transport tests
- **Integration/e2e checks:** Local suite includes the pinned A2A SDK
- **Skipped or unavailable checks:** The LAN test is opt-in and skipped. The hosted matrix was pending when this record was written.

| Command | Exit code | Result | Evidence ID |
| ------- | --------- | ------ | ----------- |
| uv pip install --python .venv/Scripts/python.exe -e ".[interop]" and .venv/Scripts/python.exe -m unittest discover -s tests -t . | 0 each | 203 tests in 92.333s, 1 skipped | EVD-001 |
| git diff --cached --check | 0 | The workflow patch has no whitespace errors. Inspection confirmed read-only contents, credential persistence disabled and pinned actions. | EVD-002 |
| gh pr checks 43 -R Matheussoranco/SELO | 8 | Four hosted jobs pending at collection | EVD-003 |

## 5. Engineering hygiene

| Category | Status | Evidence ID |
| --- | --- | --- |
| Linting | NOT_RUN | — |
| Formatting | PASS (patch whitespace) | EVD-002 |
| Static analysis | NOT_RUN | — |
| Type checking | NOT_RUN | — |
| Build | PASS (editable package build) | EVD-001 |
| Repo-specific architectural rules / coding standards | NOT_RUN | — |

## 6. Plan ledger and deviations

- **Conceptual plan:** Run the existing suite on supported interpreter versions and hosted operating systems.
- **Executed approach:** Installed the documented extra locally, ran the suite and configured the GitHub Actions matrix.
- **Deviations:** Used an isolated uv environment on Windows for the baseline. CI uses pip as documented.

## 7. Rationale and trade-offs

- **Approach taken:** One matrix job with Python 3.11, the declared minimum, and 3.12, the locally tested version.
- **Alternatives considered:** A single Linux job and Python 3.12.
- **Why rejected:** It would leave Windows and the minimum supported interpreter unverified.
- **Known trade-offs:** Four hosted jobs per run.

## 8. Exploration archive

GitHub returned no configured workflow on the original main branch. The [README test commands](../../../README.md#testes-e-limites) supply the baseline. The initial [hosted run](https://github.com/Matheussoranco/SELO/actions/runs/45680514122) is linked to the workflow commit.

## 9. Risks, rollback, and limitations

- **Residual risk / blast radius:** Hosted test execution only
- **Rollback approach:** Revert the workflow and evidence commits
- **Incomplete work:** Obtain results and independent reviews on the PR head
- **Assumptions:** Hosted jobs can resolve the same dependency extra as the local installation
- **Environment limitations:** Local baseline covers Windows, Python 3.12.10
- **Missing evidence:** Hosted results, pull-request approvals and main push
- **Follow-up work:** Record exact-SHA hosted results and reviewer conclusions in the PR

## 10. Chain of custody

The lead ran EVD-001 and EVD-002 in the dedicated sail/selo-ci worktree. The [issue](https://github.com/Matheussoranco/SELO/issues/42) records acceptance criteria. The [PR](https://github.com/Matheussoranco/SELO/pull/43) links the workflow commit and exposes hosted check results.

## 11. Machine-readable manifest

<!-- evidence-manifest:start -->
```yaml
manifest_version: "1.0"
pack_id: selo-42-05bf5da
task: {mode: github, reference: "Matheussoranco/SELO#42"}
repository:
  branch: sail/selo-ci
  base_revision: e1765cc05a824ab4e75ef6ce949fb957d32760c1
  current_revision: 05bf5daeee50607033b81f3bff9c7c6a7a02a09d
generated: {at_utc: "2026-11-25T18:59:18Z", producer: "Codex Lead"}
claims:
  - {id: CLM-001, status: PASS, evidence_ids: [EVD-001]}
  - {id: CLM-002, status: NOT_RUN, evidence_ids: [EVD-003]}
  - {id: CLM-003, status: PASS, evidence_ids: [EVD-002]}
artifacts:
  - {id: EVD-001, category: test, status: PASS, claim_ids: [CLM-001]}
  - {id: EVD-002, category: diff, status: PASS, claim_ids: [CLM-003]}
  - {id: EVD-003, category: log, status: NOT_RUN, claim_ids: [CLM-002]}
```
<!-- evidence-manifest:end -->

<!-- evidence-pack:Matheussoranco/SELO#42:05bf5daeee50607033b81f3bff9c7c6a7a02a09d -->
