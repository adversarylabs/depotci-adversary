# ci/depot — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `ci/depot`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Depot CI workflows should be as hardened as production CD: trust boundaries, pins, caches, and release gates.

**Shared engine note:** most rules here are the same detectors as `ci/github-actions` (Depot workflows are GHA-compatible) — implement them once in a shared library; this catalog adds only Depot-specific context (remote builders, depot CLI, container build cache).

## LLM strategy (required for world-class)
**Enhance:** map Depot-specific build caching + GHA-compatible security stories.
**Discover:** novel cache poisoning and privileged build topologies.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact stories, ranking, FP suppression with context. |
| **LLM discovery** | Novel issues only with concrete evidence. |

### Trust / anti-FP rules
1. Evidence required. 2. LLM-only default medium/low. 3. One finding per remediations story. 4. When unsure, omit.

## Review verdicts (staff pass)

- **P0 implement:** `pull-request.untrusted-code`, `script-injection`, `runs-on.self-hosted`, `action.unpinned`, `permissions.broad`, `secret.scope-broad`
- **P1:** `cache.poisoning`, `release.missing-gate`, `build.mutable-input`, `step.failure-masked`, `job.dependency-structure`, `oidc.missing`, `matrix.secret-log`, `timeout.missing`, `concurrency.missing`, `artifact.unsigned` (now incl. SBOM), `docker.push-latest-only`, `services.insecure`, `workflow.parse-error`, `privileged-docker`, `npm-audit.skipped`, `approve.bot-bypass`, `oidc.audience-wildcard`
- **LLM-only:** none beyond the LLM roles already embedded.
- **Cut:** `sbom.missing-on-release` — merged into `artifact.unsigned`.
- **Implementation note:** the GHA-equivalent rules (unpinned actions, script injection, self-hosted PR, cache poisoning, permissions) must share detectors with `ci/github-actions` — do not fork the logic. Apply the same cache-scoping correction documented in that catalog's `cache.poison`.

## Issue catalog

---
### 1. `depot.action.unpinned` — Unpinned third-party Depot/Actions steps

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Mutable action tags in .depot/workflows or hybrid GHA calling Depot.

**Static detection.** Parse uses: lines; require full SHA for third-party.

**LLM role.** Prioritize privileged delivery jobs.

**False-positive guards.** Official depot/* actions with documented pin policy.

**Public examples of the bad pattern:**
  - https://github.com/depot/cli
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://github.com/mheap/pin-github-action

---
### 2. `depot.secret.scope-broad` — Secrets injected at job level unnecessarily

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Job-level env secrets expose every step.

**Static detection.** Detect secrets in job env vs step env.

**LLM role.** Recommend step-scoped secrets.

**False-positive guards.** Single-step jobs.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://github.com/depot/cli

---
### 3. `depot.permissions.broad` — Over-broad token permissions in release workflows

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** contents: write across all jobs.

**Static detection.** Parse permissions blocks in Depot YAML (GHA-compatible).

**LLM role.** Least privilege per job.

**False-positive guards.** True monorepo release needing write.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
  - https://github.com/ossf/scorecard
  - https://github.com/adversarylabs/adversary — release.yml least-privilege pattern

---
### 4. `depot.pull-request.untrusted-code` — PR workflows execute untrusted build scripts

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** PR pipelines that npm install/build from PR without isolation.

**Static detection.** Detect pull_request + package manager install without hardening.

**LLM role.** LLM: is Depot sandbox enough? still flag secret exposure.

**False-positive guards.** Lint-only PR jobs without install.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://docs.depot.dev/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 5. `depot.cache.poisoning` — Cache keys shared across trust boundaries

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Build cache keys omit commit/actor isolation between PR and main.

**Static detection.** Parse cache: / actions/cache keys in Depot workflows.

**LLM role.** Recommend branch+SHA scoping.

**False-positive guards.** Read-only caches.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows
  - https://docs.depot.dev/
  - https://github.com/actions/cache

---
### 6. `depot.release.missing-gate` — Release publish without environment gate

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Publish jobs without environment: or approval gates.

**Static detection.** Detect publish/push to registry without environment.

**LLM role.** Suggest protected environments.

**False-positive guards.** Tag-only trusted maintainers private repos.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment
  - https://github.com/adversarylabs/adversary — environment: release pattern
  - https://docs.depot.dev/

---
### 7. `depot.build.mutable-input` — Build consumes mutable remote inputs

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** curl latest installers or unpinned base images in build steps.

**Static detection.** Detect curl|sh and :latest in workflow scripts.

**LLM role.** Recommend pins/checksums.

**False-positive guards.** Documented bootstrap exceptions.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/best-practices/
  - https://github.com/hadolint/hadolint
  - https://docs.depot.dev/

---
### 8. `depot.step.failure-masked` — continue-on-error on security-critical steps

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** continue-on-error: true on scan/sign/publish.

**Static detection.** Detect flag on named security steps.

**LLM role.** LLM: is step security-critical?

**False-positive guards.** Flaky e2e intentionally continued.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions
  - https://github.com/rhysd/actionlint
  - https://github.com/actions/starter-workflows

---
### 9. `depot.job.dependency-structure` — Broken needs: graph / diamond races

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** needs: cycles or publish not needing tests.

**Static detection.** Graph analysis of jobs.

**LLM role.** Explain race.

**False-positive guards.** Independent parallel jobs.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idneeds
  - https://github.com/rhysd/actionlint
  - https://docs.depot.dev/

---
### 10. `depot.oidc.missing` — Static registry tokens instead of OIDC/workload identity

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Long-lived DEPOT_TOKEN / cloud keys in secrets for every job.

**Static detection.** Detect static cloud creds patterns.

**LLM role.** Recommend short-lived OIDC where supported.

**False-positive guards.** Local Depot CLI token for private feature.

**Public examples of the bad pattern:**
  - https://docs.depot.dev/
  - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - https://github.com/aws-actions/configure-aws-credentials

---
### 11. `depot.matrix.secret-log` — Matrix values may leak secrets to logs

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Sensitive matrix axes.

**Static detection.** Heuristic key names.

**LLM role.** Suggest secrets + masking.

**False-positive guards.** Non-sensitive versions matrix.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs
  - https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
  - https://github.com/actions/runner

---
### 12. `depot.timeout.missing` — No timeouts on expensive build jobs

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** Missing timeout-minutes on Depot builders.

**Static detection.** Detect absence.

**LLM role.** Cost control.

**False-positive guards.** Known long builds with explicit long timeouts.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
  - https://docs.depot.dev/
  - https://github.com/rhysd/actionlint

---
### 13. `depot.concurrency.missing` — Missing concurrency on push-to-main builds

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Overlapping deploys/releases.

**Static detection.** Detect missing concurrency for main/tag workflows.

**LLM role.** Suggest groups.

**False-positive guards.** Pure test workflows.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-jobs/using-concurrency
  - https://github.com/adversarylabs/adversary
  - https://docs.depot.dev/

---
### 14. `depot.artifact.unsigned` — Release artifacts without checksums/SBOM/signature

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Publish steps without checksums, SBOM, or signature (absorbs former `depot.sbom.missing-on-release` — one supply-chain bundle rule).

**Static detection.** Detect gh release upload / docker push without adjacent checksums.txt, syft/sbom, or cosign steps.

**LLM role.** Recommend supply-chain bundle.

**False-positive guards.** Internal non-distributed builds.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary — release contract
  - https://github.com/sigstore/cosign
  - https://slsa.dev/

---
### 15. `depot.docker.push-latest-only` — Pushes only :latest mutable tag

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** docker push repo:latest without immutable tag.

**Static detection.** Detect push lines.

**LLM role.** Require version digests/tags.

**False-positive guards.** Internal cache images.

**Public examples of the bad pattern:**
  - https://docs.docker.com/engine/reference/commandline/push/
  - https://github.com/docker/metadata-action
  - https://docs.depot.dev/container-builds

---
### 16. `depot.services.insecure` — Service containers without auth/health

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** services: postgres without health check.

**Static detection.** Parse services: blocks.

**LLM role.** Reliability focus.

**False-positive guards.** Ephemeral unit test DBs.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-containerized-services/about-service-containers
  - https://github.com/actions/example-services
  - https://docs.depot.dev/

---
### 17. `depot.runs-on.self-hosted` — Self-hosted runners for untrusted PR builds

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Self-hosted + PR without isolation.

**Static detection.** Detect runs-on labels.

**LLM role.** Hard warn public repos.

**False-positive guards.** Private trusted runners with sandboxing documented.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security
  - https://securitylab.github.com/resources/github-actions-self-hosted-runners/
  - https://docs.depot.dev/

---
### 18. `depot.script-injection` — Untrusted contexts in run scripts

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Same class as GHA script injection inside Depot YAML.

**Static detection.** Detect github.event.* in run blocks.

**LLM role.** Same mitigations as GHA adversary.

**False-positive guards.** env: indirection partially safer.

**Public examples of the bad pattern:**
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 19. `depot.workflow.parse-error` — Invalid workflow YAML

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Parse failures hide security jobs.

**Static detection.** YAML schema validation.

**LLM role.** Report as reliability finding.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://github.com/rhysd/actionlint
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions
  - https://docs.depot.dev/cli/reference/ci

---
### 20. `depot.privileged-docker` — Docker builds with privileged flags

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** docker build --privileged or dind without need.

**Static detection.** Detect privileged flags in scripts.

**LLM role.** LLM: is privileged required for buildkit?

**False-positive guards.** Known DinD patterns with comments.

**Public examples of the bad pattern:**
  - https://docs.docker.com/engine/security/
  - https://docs.depot.dev/container-builds
  - https://github.com/docker-library/docker

---
### 21. `depot.npm-audit.skipped` — Dependency install without lockfile verification

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** npm install without ci / --frozen-lockfile.

**Static detection.** Detect package manager commands.

**LLM role.** Supply chain integrity.

**False-positive guards.** Projects without lockfiles yet (lower severity).

**Public examples of the bad pattern:**
  - https://docs.npmjs.com/cli/v10/commands/npm-ci
  - https://pnpm.io/cli/install
  - https://go.dev/ref/mod#go-mod-download

---
### 22. `depot.approve.bot-bypass` — Paths-ignore skips security workflows on critical paths

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** paths-ignore excludes lockfiles or workflows themselves.

**Static detection.** Detect paths-ignore on security-sensitive globs.

**LLM role.** LLM: does ignore skip security?

**False-positive guards.** Docs-only ignore.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onpushpull_requestpull_request_targetpathspaths-ignore
  - https://github.com/rhysd/actionlint
  - https://docs.depot.dev/

---
### 23. `depot.oidc.audience-wildcard` — OIDC token audience too broad

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Federated identity with audience * or missing sub claims.

**Static detection.** Detect cloud auth action inputs.

**LLM role.** Hardening recommendations.

**False-positive guards.** Correctly scoped examples.

**Public examples of the bad pattern:**
  - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - https://github.com/aws-actions/configure-aws-credentials
  - https://github.com/google-github-actions/auth

---

## Implementation roadmap (after approval)
1. P0 static rules + fixtures (vulnerable/clean).
2. LLM enhancement on structured signals.
3. Discovery prompts evidence-gated.
4. Precision bake-off on public repos.

**P0 priorities:** untrusted PR execution, script injection, unpinned actions, self-hosted PR builds, broad secrets/permissions, release gates.
