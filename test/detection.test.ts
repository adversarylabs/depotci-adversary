import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";

test("declares deterministic automatic detection", async () => {
  const source = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");
  const manifest = parseAdversaryManifest(source);

  assert.deepEqual(manifest.detection?.files, [
    ".depot/workflows/**",
    ".depot/**/*.yml",
    ".depot/**/*.yaml",
    "depot.json",
    "depot.yml",
    "depot.yaml",
    "depot-*.yml",
    "depot-*.yaml"
  ]);
  assert.equal(manifest.detection?.entrypoint, undefined);
});
