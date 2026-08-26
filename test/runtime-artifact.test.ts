import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the published runtime executes without the development dependency tree", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "depotci-artifact-"));
  const entrypoint = join(artifact, "dist", "index.js");
  const input = join(artifact, "input.json");
  const output = join(artifact, "output.json");
  const repository = join(projectRoot, "test", "fixtures", "good");
  const archive = join(artifact, "package.tar");
  const runtimeFiles = [
    "adversary.yaml",
    "CHECKS.md",
    "dist/index.js",
    "schemas/adversary.review.v1.schema.json",
    "THIRD_PARTY_NOTICES.md",
    "package.json",
  ];
  for (const path of runtimeFiles) {
    await execute("git", ["ls-files", "--error-unmatch", path], { cwd: projectRoot });
  }
  await execute("git", ["archive", "--format=tar", `--output=${archive}`, "HEAD", ...runtimeFiles], {
    cwd: projectRoot,
  });
  const { stdout: archiveListing } = await execute("tar", ["-tf", archive]);
  const archivePaths = archiveListing.split(/\r?\n/).filter(Boolean);
  for (const path of archivePaths) {
    assert.equal(path.split("/").includes("node_modules"), false, `${path} must not ship`);
    assert.equal(path.split("/").includes(".git"), false, `${path} must not ship`);
  }
  await execute("tar", ["-xf", archive, "-C", artifact]);
  await writeFile(input, `${JSON.stringify({ source: { path: repository } })}\n`);

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["'](?:@adversarylabs\/sdk|yaml)["']/);
  for (const path of runtimeFiles) {
    const content = await readFile(join(artifact, path), "utf8");
    assert.doesNotMatch(content, /\/Users\/[^/\s]+|\/private\/tmp\/|[A-Za-z]:\\Users\\/);
  }
  const notices = await readFile(join(artifact, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert.deepEqual([...notices.matchAll(/^## (.+?) \(/gm)].map((match) => match[1]), [
    "@adversarylabs/sdk",
    "ajv",
    "fast-deep-equal",
    "fast-uri",
    "json-schema-traverse",
    "yaml",
  ]);
  for (const section of notices.split(/^## /m).slice(1)) {
    assert.ok(section.length > 300, `expected a full license text, got ${section.length} bytes`);
    assert.match(section, /copyright|permission|redistribution|license/i);
  }

  await execute(process.execPath, [entrypoint], {
    cwd: artifact,
    env: {
      ...process.env,
      ADVERSARY_INPUT: input,
      ADVERSARY_OUTPUT: output,
      ADVERSARY_REPO: repository,
    },
  });

  const envelope = JSON.parse(await readFile(output, "utf8"));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "depotci");
  assert.equal(envelope.result.adversary.version, "0.0.20");
  assert.deepEqual(envelope.result.findings, []);
});
