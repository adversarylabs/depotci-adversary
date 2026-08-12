#!/usr/bin/env node

import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Adversary } from "@adversarylabs/sdk";
import { analyzeRepository } from "./analyze.js";
import { inspectRepository } from "./context.js";
import { discoverDepotWorkflows } from "./discover.js";
import { registerDepotRules } from "./rules/definitions.js";

export function createApp(): Adversary {
  const app = new Adversary({
    name: "depotci",
    version: "0.0.16",
    review: { maximumFindings: 8 },
  });
  registerDepotRules(app);

  app.rule("depotci.review", async (ctx) => {
    const discovery = await discoverDepotWorkflows(ctx.repoPath);
    const repository = await inspectRepository(ctx.repoPath, discovery.repositoryFiles);
    ctx.summary.files_scanned = discovery.candidates.length;
    await analyzeRepository(ctx, discovery, repository);
  });

  return app;
}

if (
  process.argv[1] !== undefined &&
  (await realpath(process.argv[1])) === (await realpath(fileURLToPath(import.meta.url)))
) {
  await createApp().runFromEnvironment();
}
