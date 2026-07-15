import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { type RepositoryContext } from "./model.js";

const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "go.sum",
  "Cargo.lock",
  "poetry.lock",
  "Pipfile.lock",
]);

export async function inspectRepository(repoPath: string, files: string[]): Promise<RepositoryContext> {
  const dockerfilePaths = files.filter(isDockerfilePath);
  const dockerfiles = await Promise.all(
    dockerfilePaths.map(async (path) => ({ path, source: await readFile(join(repoPath, path), "utf8") })),
  );

  return {
    files: new Set(files),
    lockfiles: files.filter((path) => {
      const filename = path.split("/").pop() ?? path;
      return LOCKFILE_NAMES.has(filename) || /^requirements[^/]*\.txt$/i.test(filename);
    }).sort(),
    dockerfiles: dockerfiles.sort((left, right) => left.path.localeCompare(right.path)),
  };
}

function isDockerfilePath(path: string): boolean {
  const filename = path.split("/").pop() ?? "";
  return filename === "Dockerfile" || filename.startsWith("Dockerfile.") || filename.endsWith(".dockerfile");
}
