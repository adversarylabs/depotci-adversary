# depotci

Reviews Depot CI workflows for security, correctness, reliability, caching, and performance concerns.

The `0.1.0` review is intentionally focused. It recognizes the GitHub-compatible job and step structure used by Depot workflows, reasons about Depot runners and remote builds, and reports a small set of evidence-backed findings rather than linting YAML style.

Review synthesis groups related observations by remediation, prioritizes release and publishing paths with elevated permissions or credentials, and presents the highest-value opportunities before the detailed evidence.

## Supported workflow locations

The adversary discovers workflow candidates in:

- `.depot/**/*.yml` and `.depot/**/*.yaml`
- `depot.yml` and `depot.yaml`
- `depot-*.yml` and `depot-*.yaml`

A candidate must contain a supported workflow `jobs` structure before it is analyzed. Other Depot YAML configuration is ignored. Malformed candidate workflows receive a parse finding with a file and line location.

## Initial checks

The initial release covers:

- mutable external action references;
- missing timeouts on long-running jobs;
- missing jobs, undeclared output dependencies, and artifact dependencies;
- ineffective cache keys, restore/save lifecycle gaps, and clear package-cache opportunities;
- Dockerfile ordering that defeats Depot or BuildKit layer reuse;
- trusted `pull_request_target` execution of untrusted code;
- overly broad secret and token scope;
- workflow token permissions that are broader than the job requires;
- masked build, test, scan, publish, or deployment failures;
- publish and deployment jobs without an evidenced validation gate;
- missing cancellation for obsolete pull-request builds;
- mutable or unverified external build inputs; and
- meaningful repeated dependency or build work without caching.

Informational cache and repeated-work findings are excluded by the default review policy unless informational findings are requested by the runtime.

## Build and test

Node.js 22 or newer is required.

```sh
npm ci
npm test
```

`npm test` compiles the TypeScript source and runs the deterministic fixture suite. Build without running tests with:

```sh
npm run build
```

## Run locally

From this directory:

```sh
adversary run . --repo ../some-repository
```

The manifest executes `dist/index.js`, so run `npm run build` after changing source files.

Once published, the intended registry command is:

```sh
adversary run adversarylabs/depotci --repo .
```

## Project layout

- `src/index.ts` wires discovery and analysis into the Adversary SDK.
- `src/discover.ts` performs bounded, deterministic workflow discovery.
- `src/parser.ts` strictly parses the supported workflow structure and records source locations.
- `src/model.ts` defines the normalized workflow model.
- `src/context.ts` loads only the related repository inputs needed by rules.
- `src/analyze.ts` emits observations, positive signals, and the review-level assessment.
- `src/synthesis.ts` prioritizes remediation groups and produces the overall engineering assessment.
- `src/rules/` contains rule definitions and focused analyzers.
- `test/fixtures/good/` is a clean Depot workflow example.
- `test/fixtures/unsafe-pull-request/`, `ineffective-cache/`, and the other fixture directories demonstrate individual problematic patterns.

The adversary never modifies the reviewed repository and does not require network access.

## Automatic detection

`adversary auto` selects the depotci adversary when changes include `.depot/workflows/**` or `.depot/**/*.yml`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.

## Issue catalog

What this adversary targets (P0 / P1 / LLM-only priorities, detection notes, and public pattern references) is documented in [docs/issue-catalog.md](docs/issue-catalog.md).
