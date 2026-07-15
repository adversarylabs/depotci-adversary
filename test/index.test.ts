import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/index.ts";

function fixturePath(name: string): string {
  return new URL(`../fixtures/${name}`, import.meta.url).pathname;
}

test("runs through the SDK and returns an empty structured review", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("clean") } },
    write: false,
  });

  assert.equal(output.adversary.name, "depot");
  assert.equal(output.target.filesScanned, 0);
  assert.deepEqual(output.findings, []);
  assert.deepEqual(output.observations, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});
