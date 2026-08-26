# ci/depot — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `depotci`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Depot CI

## Mission

Review Depot CI workflows for security, correctness, reliability, caching, and performance.

## In scope (fair miss if humans raised it and we did not)

- Depot/CI workflow security and reliability
- Caching mistakes that break correctness
- Performance footguns in Depot CI
- Inputs that contradict the exact metadata of a supported, immutable Depot action revision

## Out of scope (not a miss for this adversary)

- App code
- Pure GHA without Depot
- Missing-input theories that are not proven by the exact pinned action metadata and primary documentation

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
