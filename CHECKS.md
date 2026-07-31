# Checks — what ci/depot detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: `src/rules/` and `src/ci-security-core.ts`.
Regression entry: [`test/depotci.test.ts`](test/depotci.test.ts) and fixtures.

**Scope:** Depot workflow and config files (`.depot/**`, `depot.yml` / `depot.yaml`, related).

---

## Critical / High — security

### `depotci.pull-request.untrusted-code`

| | |
| --- | --- |
| **What** | Trusted workflow executes pull-request-controlled code |
| **Why** | Secrets and write tokens meet attacker-controlled steps |
| **Looks for** | Untrusted PR code on privileged Depot workflows |
| **Stays quiet when** | Metadata-only or isolated untrusted jobs |
| **Remediation** | Never run untrusted PR code with privileged secrets |

### `depotci.script-injection`

| | |
| --- | --- |
| **What** | Untrusted context interpolated into shell steps |
| **Why** | Shell breakout from event fields |
| **Looks for** | Inline untrusted expressions in run scripts |
| **Stays quiet when** | env: + quoted expansion |
| **Remediation** | Do not expand untrusted fields into shell |

### `depotci.action.unpinned`

| | |
| --- | --- |
| **What** | External action uses mutable reference |
| **Why** | Supply-chain retargeting |
| **Looks for** | uses: without full SHA |
| **Stays quiet when** | Pin to commit SHA |
| **Remediation** | Pin third-party actions |

### `depotci.permissions.broad`

| | |
| --- | --- |
| **What** | Over-broad token permissions |
| **Why** | Amplifies step compromise |
| **Looks for** | write-all or overly wide scopes |
| **Stays quiet when** | Least privilege per job |
| **Remediation** | Narrow GITHUB_TOKEN permissions |

### `depotci.secret.scope-broad`

| | |
| --- | --- |
| **What** | Secrets exposed to more jobs/steps than needed |
| **Why** | Lateral movement after step compromise |
| **Looks for** | Workflow-level secrets where job/step scope suffices |
| **Stays quiet when** | Least-scope secrets |
| **Remediation** | Pass secrets only to jobs that need them |

### `depotci.runs-on.self-hosted`

| | |
| --- | --- |
| **What** | Risky self-hosted runner usage |
| **Why** | Persistent environment retention |
| **Looks for** | self-hosted without isolation guarantees |
| **Stays quiet when** | Ephemeral/trusted runners |
| **Remediation** | Isolate untrusted work |

## Medium — reliability & performance

### `depotci.job.missing-timeout`

| | |
| --- | --- |
| **What** | Job missing timeout |
| **Why** | Hung jobs burn minutes forever |
| **Looks for** | Jobs without timeout-minutes |
| **Stays quiet when** | Explicit timeouts |
| **Remediation** | Set timeout-minutes on every job |

### `depotci.step.failure-masked`

| | |
| --- | --- |
| **What** | Failure masked (continue-on-error / always without care) |
| **Why** | Broken main looks green |
| **Looks for** | Broad continue-on-error on critical steps |
| **Stays quiet when** | Fail closed on required gates |
| **Remediation** | Only mask known-flaky non-gating steps |

### `depotci.cache.missing`

| | |
| --- | --- |
| **What** | Expected dependency cache missing |
| **Why** | Slow, non-reproducible CI |
| **Looks for** | Package ecosystems without cache |
| **Stays quiet when** | Cache restore/save with stable keys |
| **Remediation** | Cache dependencies effectively |

### `depotci.cache.unstable-key`

| | |
| --- | --- |
| **What** | Cache key unstable or ineffective |
| **Why** | Constant misses or wrong hits |
| **Looks for** | Keys that change every run or ignore lockfiles |
| **Stays quiet when** | Keys from lockfiles + runtime versions |
| **Remediation** | Include lockfile hashes in keys |

### `depotci.cache.lifecycle`

| | |
| --- | --- |
| **What** | Cache save/restore lifecycle issues |
| **Why** | Stale or never-saved caches |
| **Looks for** | Restore without save paths / wrong order |
| **Stays quiet when** | Paired restore+save |
| **Remediation** | Follow Depot/GitHub cache lifecycle |

### `depotci.build.cache-order`

| | |
| --- | --- |
| **What** | Docker/build cache steps ordered incorrectly |
| **Why** | Cache never warms |
| **Looks for** | Save before build / wrong layer order |
| **Stays quiet when** | Restore → build → save |
| **Remediation** | Order cache around the build |

### `depotci.build.mutable-input`

| | |
| --- | --- |
| **What** | Mutable build inputs |
| **Why** | Non-reproducible artifacts |
| **Looks for** | Unpinned base images or floating refs in build |
| **Stays quiet when** | Pinned digests/versions |
| **Remediation** | Pin build inputs |

### `depotci.workflow.concurrency`

| | |
| --- | --- |
| **What** | Missing or weak concurrency controls |
| **Why** | Overlapping deploys/races |
| **Looks for** | No concurrency group on deploy workflows |
| **Stays quiet when** | concurrency groups with cancel-in-progress where safe |
| **Remediation** | Serialize privileged deploys |

### `depotci.release.missing-gate`

| | |
| --- | --- |
| **What** | Release/publish path missing required gates |
| **Why** | Ship without test/security signals |
| **Looks for** | Publish jobs without needs: on tests |
| **Stays quiet when** | Require green gates before release |
| **Remediation** | Gate releases on verification jobs |

### `depotci.job.dependency-structure`

| | |
| --- | --- |
| **What** | Job dependency structure problems |
| **Why** | Skipped gates or redundant work |
| **Looks for** | Broken needs: graphs |
| **Stays quiet when** | Clear DAG of required jobs |
| **Remediation** | Make required checks explicit |

### `depotci.workflow.redundant-work`

| | |
| --- | --- |
| **What** | Redundant work across jobs |
| **Why** | Wasted CI time |
| **Looks for** | Duplicate install/build without artifacts |
| **Stays quiet when** | Share artifacts/caches |
| **Remediation** | Build once; reuse |
