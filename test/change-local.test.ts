import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated edit keeps holistic checks for the changed workflow", async () => {
  const repo = await repositoryWithWorkflow(workflow("actions/checkout@v4", "old diagnostic"));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), workflow("actions/checkout@v4", "new diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.action.unpinned"), false);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.job.missing-timeout"), true);
});

test("change mode suppresses findings from unchanged workflows", async () => {
  const repo = await repositoryWithWorkflow(workflow("actions/checkout@v4", "changed diagnostic"));
  const unchangedPath = ".depot/workflows/legacy.yml";
  await writeFile(join(repo, unchangedPath), workflow("actions/checkout@v4", "legacy diagnostic"));
  await execute("git", ["add", unchangedPath], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "add legacy workflow"], { cwd: repo });

  const changedPath = ".depot/workflows/ci.yml";
  await writeFile(join(repo, changedPath), workflow("actions/checkout@v4", "updated diagnostic"));

  const result = await changedReview(repo, [changedPath]);
  assert.equal(result.findings.some((finding) =>
    finding.evidence.some((evidence) => evidence.location?.file === unchangedPath)), false);
});

test("all mode includes findings from every workflow", async () => {
  const repo = await repositoryWithWorkflow(workflow("actions/checkout@v4", "changed diagnostic"));
  const secondPath = ".depot/workflows/legacy.yml";
  await writeFile(join(repo, secondPath), workflow("actions/checkout@v4", "legacy diagnostic"));

  const result = await fullReview(repo);
  assert.equal(result.findings.some((finding) =>
    finding.evidence.some((evidence) => evidence.location?.file === secondPath)), true);
});

test("a changed action reference remains eligible with unchanged workflow context", async () => {
  const repo = await repositoryWithWorkflow(workflow("actions/checkout@0123456789012345678901234567890123456789", "diagnostic"));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), workflow("actions/checkout@v4", "diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.action.unpinned"), true);
});

test("deleting unrelated workflow text does not make an adjacent legacy action eligible", async () => {
  const original = workflow("actions/checkout@v4", "delete me");
  const repo = await repositoryWithWorkflow(original);
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), original.replace('      - name: Diagnostic\n        run: echo "delete me"\n', ""));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.action.unpinned"), false);
});

test("an added workflow makes every direct semantic anchor eligible", async () => {
  const repo = await emptyRepository();
  const path = ".depot/workflows/added.yml";
  await mkdir(join(repo, ".depot/workflows"), { recursive: true });
  await writeFile(join(repo, path), workflow("actions/checkout@v4", "diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.action.unpinned"), true);
});

test("authority-dependent action findings remain holistic", async () => {
  const repo = await repositoryWithWorkflow(privilegedWorkflow("read"));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), privilegedWorkflow("write"));

  const result = await changedReview(repo, [path]);
  assert.equal(
    result.findings.some((finding) =>
      finding.ruleId === "depotci.action.unpinned" &&
      finding.groupKey === "depotci.action.unpinned:privileged"),
    true,
  );
});

test("an added unsupported pinned-action input is anchored to the input key", async () => {
  const repo = await repositoryWithWorkflow(cacheMountWorkflow(""));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), cacheMountWorkflow("          write-lock: true\n"));

  const result = await changedReview(repo, [path]);
  const finding = result.findings.find((item) => item.ruleId === "depotci.action.unsupported-input");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.data?.input, "write-lock");
  assert.equal(finding.evidence[0]?.location?.line, 12);
});

test("an unrelated edit does not activate an existing unsupported action input", async () => {
  const repo = await repositoryWithWorkflow(cacheMountWorkflow("          write-lock: true\n", "old diagnostic"));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), cacheMountWorkflow("          write-lock: true\n", "new diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((item) => item.ruleId === "depotci.action.unsupported-input"), false);
});

async function repositoryWithWorkflow(source: string): Promise<string> {
  const repo = await emptyRepository();
  await mkdir(join(repo, ".depot/workflows"), { recursive: true });
  await writeFile(join(repo, ".depot/workflows/ci.yml"), source);
  await execute("git", ["add", ".depot/workflows/ci.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function emptyRepository(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "depotci-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, ".gitignore"), "\n");
  await execute("git", ["add", ".gitignore"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "initial"], { cwd: repo });
  return repo;
}

function workflow(action: string, diagnostic: string): string {
  return `name: CI
on: push
jobs:
  build:
    runs-on: depot-ubuntu-latest
    steps:
      - uses: ${action}
      - run: npm test
      - name: Diagnostic
        run: echo ${JSON.stringify(diagnostic)}
`;
}

function privilegedWorkflow(permission: "read" | "write"): string {
  return `name: CI
on: push
permissions:
  contents: ${permission}
jobs:
  build:
    runs-on: depot-ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
      - name: Diagnostic
        run: echo diagnostic
`;
}

function cacheMountWorkflow(extraInput: string, diagnostic = "diagnostic"): string {
  return `name: CI
on: push
jobs:
  build:
    runs-on: depot-ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: depot/cache-mount@c4ccf77f90f7fa7df6a002813c0b13f6a5943063
        with:
          path: /mnt/cache
          name: cache
${extraInput}      - name: Diagnostic
        run: echo ${JSON.stringify(diagnostic)}
`;
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}

async function fullReview(repoPath: string) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: [],
      },
    },
  });
}
