import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
  const schema = join(artifact, "schemas", "adversary.review.v1.schema.json");
  const input = join(artifact, "input.json");
  const output = join(artifact, "output.json");
  const repository = join(projectRoot, "test", "fixtures", "good");

  await mkdir(dirname(entrypoint), { recursive: true });
  await mkdir(dirname(schema), { recursive: true });
  await copyFile(join(projectRoot, "dist", "index.js"), entrypoint);
  assert.equal(
    await readFile(join(projectRoot, "schemas", "adversary.review.v1.schema.json"), "utf8"),
    await readFile(
      join(
        projectRoot,
        "node_modules",
        "@adversarylabs",
        "sdk",
        "schemas",
        "adversary.review.v1.schema.json",
      ),
      "utf8",
    ),
    "the packaged protocol schema must match the locked SDK",
  );
  await copyFile(
    join(projectRoot, "schemas", "adversary.review.v1.schema.json"),
    schema,
  );
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');
  await writeFile(input, `${JSON.stringify({ source: { path: repository } })}\n`);

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["'](?:@adversarylabs\/sdk|yaml)["']/);

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
  assert.deepEqual(envelope.result.findings, []);
});
