# ci/depot

**ci/depot** reviews Depot CI workflows for **security, correctness, reliability, caching, and performance** concerns on Depot runners and remote builds — including unpinned actions, secret scope, untrusted PR code, cache effectiveness, and release gates.

It is a **Depot CI domain reviewer**. It understands GitHub-compatible job/step structure as used by Depot, and prefers evidence-backed findings over YAML style.

## What it does

1. **Discovers** Depot workflow candidates (`.depot/workflows/**`, `depot.yml`, etc.).
2. **Runs deterministic detectors** for security and operational rules.
3. **Synthesizes a review** that groups related observations by remediation and prioritizes high-privilege release paths.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Security | Unpinned actions; broad permissions; script injection; untrusted PR code |
| Secrets | Over-broad secret scope on jobs/steps |
| Cache | Missing, unstable, or mis-ordered cache keys |
| Jobs | Missing timeouts; masked failures; dependency structure |
| Release | Missing release gates on privileged publish paths |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Pure GitHub Actions workflows under `.github/workflows` | [`ci/github-actions`](https://github.com/adversarylabs/githubactions-adversary) |
| Committed secrets anywhere | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
