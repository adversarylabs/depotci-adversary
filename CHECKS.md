# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `depotci.action.unpinned` | Critical | External action uses mutable reference |
| `depotci.build.cache-order` | Medium | Docker/build cache steps ordered incorrectly |
| `depotci.build.mutable-input` | Medium | Mutable build inputs |
| `depotci.cache.lifecycle` | Medium | Cache save/restore lifecycle issues |
| `depotci.cache.missing` | Medium | Expected dependency cache missing |
| `depotci.cache.unstable-key` | Medium | Cache key unstable or ineffective |
| `depotci.job.dependency-structure` | Medium | Job dependency structure problems |
| `depotci.job.missing-timeout` | Medium | Job missing timeout |
| `depotci.permissions.broad` | Critical | Over-broad token permissions |
| `depotci.pull-request.untrusted-code` | Critical | Trusted workflow executes pull-request-controlled code |
| `depotci.release.missing-gate` | Medium | Release/publish path missing required gates |
| `depotci.runs-on.self-hosted` | Critical | Risky self-hosted runner usage |
| `depotci.script-injection` | Critical | Untrusted context interpolated into shell steps |
| `depotci.secret.scope-broad` | Critical | Secrets exposed to more jobs/steps than needed |
| `depotci.step.failure-masked` | Medium | Failure masked (continue-on-error / always without care) |
| `depotci.workflow.concurrency` | Medium | Missing or weak concurrency controls |
| `depotci.workflow.redundant-work` | Medium | Redundant work across jobs |
