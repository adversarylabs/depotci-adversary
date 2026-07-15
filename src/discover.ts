import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { type DepotWorkflow, type ParseFailure } from "./model.js";
import { parseDepotWorkflow } from "./parser.js";

const MAX_DISCOVERY_FILES = 5000;
const SKIPPED_DIRECTORIES = new Set([
  ".adversary",
  ".git",
  ".hg",
  ".next",
  ".svn",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

export interface DiscoveryResult {
  workflows: DepotWorkflow[];
  failures: ParseFailure[];
  candidates: string[];
  repositoryFiles: string[];
}

export async function discoverDepotWorkflows(repoPath: string): Promise<DiscoveryResult> {
  const repositoryFiles = await walkRepository(repoPath);
  const candidates = repositoryFiles.filter(isDepotWorkflowCandidate).sort();
  const workflows: DepotWorkflow[] = [];
  const failures: ParseFailure[] = [];

  for (const path of candidates) {
    const source = await readFile(join(repoPath, path), "utf8");
    const result = parseDepotWorkflow(path, source);
    if (result.kind === "workflow") {
      workflows.push(result.workflow);
    } else if (result.kind === "failure" && isLikelyWorkflowSource(path, source)) {
      failures.push(result.failure);
    }
  }

  return {
    workflows: workflows.sort((left, right) => left.path.localeCompare(right.path)),
    failures: failures.sort((left, right) => left.path.localeCompare(right.path) || left.line - right.line),
    candidates,
    repositoryFiles,
  };
}

function isLikelyWorkflowSource(path: string, source: string): boolean {
  const filename = path.split("/").pop()?.toLowerCase() ?? "";
  return path.toLowerCase().startsWith(".depot/workflows/") ||
    filename === "depot.yml" ||
    filename === "depot.yaml" ||
    /^depot-.+\.ya?ml$/.test(filename) ||
    /^\s*(?:on|jobs)\s*:/m.test(source);
}

export async function walkRepository(root: string, limit = MAX_DISCOVERY_FILES): Promise<string[]> {
  const files: string[] = [];

  async function visit(relativeDirectory: string): Promise<void> {
    if (files.length >= limit) {
      return;
    }
    const directory = join(root, relativeDirectory);
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (files.length >= limit) {
        return;
      }
      const relativePath = relativeDirectory.length === 0 ? entry.name : join(relativeDirectory, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) {
          await visit(relativePath);
        }
      } else if (entry.isFile()) {
        files.push(toPosixPath(relativePath));
      }
    }
  }

  await visit("");
  return files.sort();
}

export function isDepotWorkflowCandidate(path: string): boolean {
  const normalized = path.toLowerCase();
  const filename = normalized.split("/").pop() ?? normalized;
  const yaml = filename.endsWith(".yml") || filename.endsWith(".yaml");
  if (!yaml) {
    return false;
  }
  return normalized.startsWith(".depot/") || filename === "depot.yml" || filename === "depot.yaml" || /^depot-.+\.ya?ml$/.test(filename);
}

function toPosixPath(path: string): string {
  return path.split(sep).join("/");
}
