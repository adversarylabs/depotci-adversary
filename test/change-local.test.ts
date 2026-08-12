import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated workflow edit suppresses a legacy direct finding but preserves holistic checks", async () => {
  const repo = await repositoryWithWorkflow(workflow("actions/checkout@v4", "old diagnostic"));
  const path = ".depot/workflows/ci.yml";
  await writeFile(join(repo, path), workflow("actions/checkout@v4", "new diagnostic"));

  const result = await changedReview(repo, [path]);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.action.unpinned"), false);
  assert.equal(result.findings.some((finding) => finding.ruleId === "depotci.job.missing-timeout"), true);
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
