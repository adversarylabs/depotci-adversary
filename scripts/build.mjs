import { build } from "esbuild";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import {
  bundledPackageNames,
  RUNTIME_LICENSE_CATALOG,
  validateLicenseInventory,
} from "./license-inventory.mjs";

await rm("dist", { recursive: true, force: true });

const result = await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  metafile: true,
  preserveSymlinks: true,
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
});

const bundledPackages = validateLicenseInventory(
  bundledPackageNames(Object.keys(result.metafile.inputs)),
);
const noticeSections = await Promise.all(bundledPackages.map(async (name) => {
  const entry = RUNTIME_LICENSE_CATALOG.get(name);
  if (entry === undefined) throw new Error(`missing full license text mapping for bundled package ${name}`);
  const text = await readFile(entry.path, "utf8");
  if (text.trim().length === 0) throw new Error(`bundled dependency license is empty: ${entry.path}`);
  const normalized = text.replaceAll("\r\n", "\n").split("\n").map((line) => line.trimEnd()).join("\n").trimEnd();
  return `## ${name} (${entry.license})\n\n${normalized}`;
}));
await writeFile("THIRD_PARTY_NOTICES.md", `# Third-party notices\n\n${noticeSections.join("\n\n")}\n`);

await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);
