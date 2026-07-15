#!/usr/bin/env node

import { Adversary } from "@adversarylabs/sdk";

export function createApp(): Adversary {
  const app = new Adversary({ name: "depot" });

  app.rule("depot.review", (ctx) => {
    // Detection is intentionally left for a later implementation.
    ctx.summary.files_scanned = 0;
  });

  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().runFromEnvironment();
}
