import assert from "node:assert/strict";
import test from "node:test";
import {
  TerminalRenderer,
  createAdversaryRunEnvelope,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import { discoverDepotWorkflows } from "../src/discover.ts";
import { parseDepotWorkflow } from "../src/parser.ts";
import { analyzeActions } from "../src/rules/actions.ts";

function fixturePath(name: string): string {
  return new URL(`./fixtures/${name}`, import.meta.url).pathname;
}

async function review(name: string, options: { raw?: boolean; informational?: boolean } = {}) {
  return createApp().run({
    input: { source: { path: fixturePath(name) } },
    includeRawObservations: options.raw,
    review: { includeInformational: options.informational },
  });
}

test("discovers supported Depot workflows and ignores unrelated Depot YAML", async () => {
  const good = await discoverDepotWorkflows(fixturePath("good"));
  assert.deepEqual(good.candidates, [".depot/settings.yaml", ".depot/workflows/ci.yml"]);
  assert.deepEqual(good.workflows.map((workflow) => workflow.path), [".depot/workflows/ci.yml"]);
  assert.equal(good.failures.length, 0);

  const unrelated = await discoverDepotWorkflows(fixturePath("unrelated"));
  assert.equal(unrelated.candidates.length, 2);
  assert.equal(unrelated.workflows.length, 0);
  assert.equal(unrelated.failures.length, 0);
});

test("strict YAML failures include a useful file and line", async () => {
  const output = await review("malformed");
  const finding = output.findings.find((item) => item.ruleId === "depotci.workflow.parse-error");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.file, ".depot/workflows/ci.yml");
  assert.equal(finding.evidence[0]?.location?.line, 6);
  assert.match(String(finding.evidence[0]?.data?.error), /yaml|flow sequence|unexpected/i);

  const structure = parseDepotWorkflow("depot.yml", "name: invalid\njobs: []\n");
  assert.equal(structure.kind, "failure");
  if (structure.kind === "failure") {
    assert.equal(structure.failure.line, 2);
    assert.match(structure.failure.message, /jobs field must be a mapping/i);
  }
});

test("routine unpinned action occurrences share one remediation group while local actions are ignored", async () => {
  const output = await review("unpinned-actions", { raw: true });
  const observations = output.rawObservations?.filter((item) => item.ruleId === "depotci.action.unpinned") ?? [];
  assert.equal(observations.length, 2);
  assert.equal(new Set(observations.map((item) => item.groupKey)).size, 1);
  assert.equal(observations.every((item) => item.subject === "actions/checkout"), true);

  const finding = output.findings.find((item) => item.ruleId === "depotci.action.unpinned");
  assert.ok(finding);
  assert.equal(finding.evidence.length, 2);
});

test("checks explicit inputs against the exact pinned Depot action contract", async () => {
  const invalid = await review("unsupported-action-input");
  const finding = invalid.findings.find((item) => item.ruleId === "depotci.action.unsupported-input");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.file, ".depot/workflows/pr.yml");
  assert.equal(finding.evidence[0]?.location?.line, 13);
  assert.equal(finding.evidence[0]?.data?.input, "write-lock");
  assert.deepEqual(finding.evidence[0]?.data?.supportedInputs, ["debug", "name", "path"]);
  assert.equal(
    finding.evidence[0]?.data?.contractSource,
    "https://github.com/depot/cache-mount/blob/v1.2.1/action.yml",
  );
});

test("keeps the source-derived writable cache-mount configuration quiet", async () => {
  const output = await review("action-input-contract");
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.action.unsupported-input"), false);
  assert.equal(output.findings.some((item) => /write-lock/i.test(JSON.stringify(item))), false);
});

test("fails closed when the action revision or action path lacks an exact contract", () => {
  const cases = [
    "depot/cache-mount@v1.2.1",
    "depot/cache-mount@0123456789012345678901234567890123456789",
    "depot/cache-mount/subpath@c4ccf77f90f7fa7df6a002813c0b13f6a5943063",
  ];
  for (const action of cases) {
    const parsed = parseDepotWorkflow(".depot/workflows/pr.yml", `name: PR
on: pull_request
jobs:
  review:
    runs-on: depot-ubuntu-latest
    steps:
      - uses: ${action}
        with:
          path: /mnt/cache
          name: cache
          write-lock: true
`);
    assert.equal(parsed.kind, "workflow");
    if (parsed.kind === "workflow") {
      assert.equal(
        analyzeActions(parsed.workflow).some((item) => item.ruleId === "depotci.action.unsupported-input"),
        false,
      );
    }
  }
});

test("fails closed when action inputs are inherited through a YAML merge", () => {
  const parsed = parseDepotWorkflow(".depot/workflows/pr.yml", `name: PR
on: pull_request
inputs: &cache-inputs
  path: /mnt/cache
  name: cache
  write-lock: true
jobs:
  review:
    runs-on: depot-ubuntu-latest
    steps:
      - uses: depot/cache-mount@c4ccf77f90f7fa7df6a002813c0b13f6a5943063
        with:
          <<: *cache-inputs
`);
  assert.equal(parsed.kind, "workflow");
  if (parsed.kind === "workflow") {
    assert.equal(
      analyzeActions(parsed.workflow).some((item) => item.ruleId === "depotci.action.unsupported-input"),
      false,
    );
  }
});

test("action findings group by remediation and prioritize production authority", async () => {
  const output = await review("review-synthesis", { raw: true });
  const findings = output.findings.filter((item) => item.ruleId === "depotci.action.unpinned");
  assert.equal(findings.length, 2);

  const privileged = findings.find((item) => item.groupKey === "depotci.action.unpinned:privileged-delivery");
  assert.ok(privileged);
  assert.equal(privileged.title, "Release workflows execute mutable actions with production authority");
  assert.equal(privileged.severity, "high");
  assert.deepEqual(
    privileged.evidence.map((item) => item.data?.action).sort(),
    ["actions/checkout", "elasticclaw/actions", "softprops/action-gh-release"],
  );
  assert.match(privileged.summary, /actions\/checkout \(1\).*elasticclaw\/actions \(1\).*softprops\/action-gh-release \(1\)/s);
  assert.match(privileged.whyItMatters ?? "", /repository write permissions.*publishing or deployment credentials/s);

  const policy = findings.find((item) => item.groupKey === "depotci.action.unpinned:routine");
  assert.ok(policy);
  assert.equal(policy.title, "Repository-wide GitHub Action pinning policy");
  assert.equal(policy.severity, "low");
  assert.deepEqual(
    policy.evidence.map((item) => item.data?.action).sort(),
    ["actions/checkout", "actions/setup-node", "actions/upload-artifact"],
  );
  assert.equal(new Set(findings.map((item) => item.recommendation)).size, 2);
});

test("primary opportunities and assessment explain what to fix first", async () => {
  const output = await review("review-synthesis");
  const repeated = await review("review-synthesis");
  const priorities = output.observations.find((item) => item.key === "depotci.primary-opportunities");
  assert.ok(priorities);
  assert.match(priorities.summary, /^Primary opportunities\n1\. Pin release-critical GitHub Actions by full commit SHA\./);
  assert.match(priorities.summary, /Establish a repository-wide GitHub Action pinning policy/);
  assert.match(priorities.summary, /Add explicit timeout-minutes to long-running jobs/);

  assert.equal(output.assessment?.risk, "high");
  assert.match(output.assessment?.summary ?? "", /release and publishing paths rely on mutable third-party actions/);
  assert.match(output.assessment?.summary ?? "", /repository write permissions \(contents\)/);
  assert.match(output.assessment?.summary ?? "", /ELASTICCLAW_TOKEN/);
  assert.equal(output.findings[0]?.groupKey, "depotci.action.unpinned:privileged-delivery");
  assert.match(output.opinion?.summary ?? "", /pin release-critical GitHub Actions.*before relying/);
  assert.deepEqual(repeated, output);
});

test("release validation and explicit expensive-job timeouts are factual positive signals", async () => {
  const output = await review("review-synthesis");
  assert.deepEqual(output.positives.map((positive) => positive.key), [
    "depotci.jobs.timeouts:.depot/workflows/release.yml",
    "depotci.release.version-validation:.depot/workflows/release.yml",
  ]);
  const validation = output.positives.find((positive) => positive.key === "depotci.release.version-validation:.depot/workflows/release.yml");
  assert.deepEqual(validation?.evidence?.map((item) => item.label), ["publish/Check version matches tag"]);
});

test("missing timeouts are grouped across long-running jobs", async () => {
  const output = await review("missing-timeout");
  const finding = output.findings.find((item) => item.ruleId === "depotci.job.missing-timeout");
  assert.ok(finding);
  assert.equal(finding.evidence.length, 2);
  assert.deepEqual(finding.evidence.map((item) => item.data?.job), ["build", "integration-test"]);
});

test("dependency graph validation catches missing jobs and undeclared output producers", async () => {
  const output = await review("broken-dependencies");
  const finding = output.findings.find((item) => item.ruleId === "depotci.job.dependency-structure");
  assert.ok(finding);
  assert.equal(finding.evidence.length, 2);
  assert.deepEqual(
    finding.evidence.map((item) => item.data?.issue).sort(),
    ["missing-job", "undeclared-output-dependency"],
  );
});

test("cache key analysis accepts lockfile-aware compatibility keys and flags commit-specific keys", async () => {
  const effective = await review("effective-cache");
  assert.equal(effective.findings.some((item) => item.ruleId === "depotci.cache.unstable-key"), false);

  const ineffective = await review("ineffective-cache");
  const finding = ineffective.findings.find((item) => item.ruleId === "depotci.cache.unstable-key");
  assert.ok(finding);
  assert.match(JSON.stringify(finding.evidence[0]?.data?.reasons), /commit identity|lockfile digest/);
});

test("cache lifecycle and clear missing-cache opportunities are reported", async () => {
  const lifecycle = await review("cache-lifecycle");
  assert.equal(lifecycle.findings.some((item) => item.ruleId === "depotci.cache.lifecycle"), true);

  const missing = await review("missing-cache", { informational: true });
  const finding = missing.findings.find((item) => item.ruleId === "depotci.cache.missing");
  assert.ok(finding);
  assert.deepEqual(finding.evidence[0]?.data?.lockfiles, ["package-lock.json"]);
});

test("Dockerfile ordering is reviewed only when Depot builds the image", async () => {
  const output = await review("docker-cache-order");
  const finding = output.findings.find((item) => item.ruleId === "depotci.build.cache-order");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.file, "Dockerfile");
  assert.equal(finding.evidence[0]?.location?.line, 3);
  assert.equal(finding.evidence[0]?.data?.dependencyInstallLine, 4);
});

test("trusted pull-request execution identifies the trigger, capability boundary, and execution step", async () => {
  const output = await review("unsafe-pull-request");
  const finding = output.findings.find((item) => item.ruleId === "depotci.pull-request.untrusted-code");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
  assert.equal(finding.evidence[0]?.data?.trigger, "pull_request_target");
  assert.equal(finding.evidence[0]?.data?.executionStep, "Execute tests");
  assert.match(JSON.stringify(finding.evidence[0]?.data?.capabilities), /PUBLISH_TOKEN|write permissions|Depot runner|shared cache/);
});

test("workflow-scoped secrets are reported without including secret values", async () => {
  const output = await review("secret-scope");
  const finding = output.findings.find((item) => item.ruleId === "depotci.secret.scope");
  assert.ok(finding);
  assert.deepEqual(finding.evidence[0]?.data?.secretNames, ["DEPLOY_TOKEN"]);
  assert.doesNotMatch(JSON.stringify(finding), /\$\{\{\s*secrets\./);
});

test("required validation failure masking is reported", async () => {
  const output = await review("masked-failure");
  const finding = output.findings.find((item) => item.ruleId === "depotci.step.failure-masked");
  assert.ok(finding);
  assert.match(JSON.stringify(finding.evidence[0]?.data?.patterns), /\|\| true/);
});

test("publish jobs must depend on or perform validation before delivery", async () => {
  const output = await review("missing-release-gate");
  const finding = output.findings.find((item) => item.ruleId === "depotci.release.missing-gate");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.data?.job, "publish");
  assert.deepEqual(finding.evidence[0]?.data?.declaredNeeds, []);
});

test("expensive pull-request workflows recommend cancellation without affecting release-only workflows", async () => {
  const output = await review("concurrency");
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.workflow.concurrency"), true);

  const release = await review("missing-release-gate");
  assert.equal(release.findings.some((item) => item.ruleId === "depotci.workflow.concurrency"), false);
});

test("mutable remote scripts are identified separately from action pinning", async () => {
  const output = await review("mutable-input");
  const finding = output.findings.find((item) => item.ruleId === "depotci.build.mutable-input");
  assert.ok(finding);
  assert.match(JSON.stringify(finding.evidence[0]?.data?.reasons), /mutable branch|integrity check/);
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.action.unpinned"), false);
});

test("remote commands shown in generated guidance are not treated as executed downloads", async () => {
  const output = await review("review-synthesis");
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.build.mutable-input"), false);
});

test("clean workflows produce concise positives and no material findings", async () => {
  const output = await review("good", { raw: true });
  assert.equal(output.adversary.name, "depotci");
  assert.match(output.adversary.version, /^\d+\.\d+\.\d+$/);
  assert.equal(output.target.filesScanned, 2);
  assert.deepEqual(output.findings, []);
  assert.deepEqual(output.rawObservations, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
  assert.deepEqual(output.positives.map((positive) => positive.key), [
    "depotci.actions.immutable:.depot/workflows/ci.yml",
    "depotci.jobs.timeouts:.depot/workflows/ci.yml",
  ]);
});

test("immutable pull-request feedback jobs may post reviews without a broad-permissions finding", async () => {
  const output = await review("pr-review", { raw: true });
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.permissions.broad"), false);
  assert.equal(output.findings.some((item) => item.ruleId === "depotci.action.unpinned"), false);
});

test("finding and evidence ordering is deterministic", async () => {
  const first = await review("unsafe-pull-request", { raw: true });
  const second = await review("unsafe-pull-request", { raw: true });
  assert.deepEqual(second, first);
  assert.deepEqual(first.findings.map((finding) => finding.ruleId), [
    "depotci.pull-request.untrusted-code",
    "depotci.permissions.broad",
  ]);
});

test("terminal output excludes raw observation metadata", async () => {
  const output = await review("unpinned-actions", { raw: true });
  const rendered: string[] = [];
  new TerminalRenderer((text) => rendered.push(text)).render(output);
  const terminal = rendered.join("");
  assert.match(terminal, /Repository-wide GitHub Action pinning policy/);
  assert.doesNotMatch(terminal, /referenceType|sensitivePath|rawObservations|groupKey/);
});

test("JSON output uses the canonical review protocol", async () => {
  const output = await review("good");
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(output)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "depotci");
  assert.equal(Array.isArray(envelope.result.findings), true);
});
