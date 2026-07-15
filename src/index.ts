#!/usr/bin/env node

import { Adversary } from "@adversarylabs/sdk";
import { analyzeRepository } from "./analyze.js";
import { inspectRepository } from "./context.js";
import { discoverDepotWorkflows } from "./discover.js";
import { registerDepotRules } from "./rules/definitions.js";

export function createApp(): Adversary {
  const app = new Adversary({
    name: "depotci",
    version: "0.1.0",
    review: { maximumFindings: 8 },
  });
  registerDepotRules(app);

  app.rule("depotci.review", async (ctx) => {
    const discovery = await discoverDepotWorkflows(ctx.repoPath);
    const repository = await inspectRepository(ctx.repoPath, discovery.repositoryFiles);
    ctx.summary.files_scanned = discovery.candidates.length;
    analyzeRepository(ctx, discovery, repository);
  });

  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().runFromEnvironment();
}
