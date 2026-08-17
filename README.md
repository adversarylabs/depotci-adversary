# Depot CI adversary

Reviews Depot CI workflows for security, correctness, reliability, caching, and performance concerns.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Depot CI workflow files, jobs, steps, permissions, caches, runner selection, and release dependencies.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns CI configuration in this platform domain. Application code, container definitions, and infrastructure resources remain with their specialist adversaries.
