import assert from "node:assert/strict";
import test from "node:test";
import { ACTIONLINT_VERSION, runActionlint } from "../src/actionlint.js";

test("runs the vendored actionlint engine deterministically", async () => {
  assert.equal(ACTIONLINT_VERSION, "1.7.12");
  const errors = await runActionlint(".depot/workflows/invalid.yml", `
on: unknown_event
jobs:
  test:
    runs-on: depot-ubuntu-latest
    steps:
      - run: echo ok
`, ["depot-ubuntu-latest"]);

  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.kind, "events");
  assert.match(errors[0]?.message ?? "", /unknown Webhook event/);
  assert.equal(errors[0]?.line, 2);
});

test("accepts Depot runner labels in otherwise valid workflows", async () => {
  const errors = await runActionlint(".depot/workflows/valid.yml", `
on: push
jobs:
  test:
    runs-on: depot-ubuntu-latest
    steps:
      - run: echo ok
`, ["depot-ubuntu-latest"]);
  assert.deepEqual(errors, []);
});
