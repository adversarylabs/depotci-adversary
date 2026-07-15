import { type DepotWorkflow, type RepositoryContext, type WorkflowJob, type WorkflowStep, expressionText } from "../model.js";
import { hasCacheUse, isBuildAction } from "./helpers.js";
import { type Detection } from "./types.js";

export function analyzeCaching(workflow: DepotWorkflow, repository: RepositoryContext): Detection[] {
  return [
    ...unstableCacheKeys(workflow),
    ...missingDependencyCaches(workflow, repository),
    ...cacheLifecycle(workflow),
    ...dockerfileCacheOrder(workflow, repository),
  ];
}

function unstableCacheKeys(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  for (const job of workflow.jobs) {
    for (const step of job.steps.filter(isCacheStep)) {
      const key = typeof step.with.key === "string" ? step.with.key : undefined;
      if (key === undefined) {
        continue;
      }
      const reasons = cacheKeyWeaknesses(job, step, key);
      if (reasons.length === 0) {
        continue;
      }
      detections.push({
        ruleId: "depotci.cache.unstable-key",
        subject: `${job.id}/${step.name}`,
        groupKey: `depotci.cache.unstable-key:${workflow.path}`,
        file: workflow.path,
        line: step.location.line,
        snippet: step.location.snippet,
        label: `${job.id}/${step.name} uses an ineffective cache key`,
        data: { workflow: workflow.name, job: job.id, step: step.name, key, reasons },
      });
    }
  }
  return detections;
}

function missingDependencyCaches(workflow: DepotWorkflow, repository: RepositoryContext): Detection[] {
  const detections: Detection[] = [];
  for (const job of workflow.jobs) {
    if (hasCacheUse(job)) {
      continue;
    }
    const manager = packageManagerInstall(job);
    if (manager === undefined) {
      continue;
    }
    const lockfiles = lockfilesForManager(repository.lockfiles, manager);
    if (lockfiles.length === 0) {
      continue;
    }
    const step = job.steps.find((candidate) => installPattern(manager).test(candidate.run ?? ""));
    if (step === undefined) {
      continue;
    }
    detections.push({
      ruleId: "depotci.cache.missing",
      subject: `${workflow.path}:${manager}`,
      groupKey: `depotci.cache.missing:${manager}`,
      file: workflow.path,
      line: step.location.line,
      snippet: step.location.snippet,
      label: `${job.id}/${step.name} installs ${manager} dependencies without an evident package cache`,
      data: { workflow: workflow.name, job: job.id, step: step.name, packageManager: manager, lockfiles },
    });
  }
  return detections;
}

function cacheLifecycle(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  for (const job of workflow.jobs) {
    const restores = job.steps.filter((step) => /actions\/cache\/restore@/i.test(step.uses ?? ""));
    const saves = job.steps.filter((step) => /actions\/cache\/save@/i.test(step.uses ?? ""));
    for (const restore of restores) {
      const restoreKey = typeof restore.with.key === "string" ? restore.with.key : undefined;
      const matchingSave = saves.find((save) => save.index > restore.index && keysCorrespond(restoreKey, typeof save.with.key === "string" ? save.with.key : undefined));
      if (matchingSave !== undefined) {
        continue;
      }
      detections.push({
        ruleId: "depotci.cache.lifecycle",
        subject: `${job.id}/${restore.name}`,
        groupKey: `depotci.cache.lifecycle:${workflow.path}`,
        file: workflow.path,
        line: restore.location.line,
        snippet: restore.location.snippet,
        label: `${job.id}/${restore.name} restores a cache without a later matching save`,
        data: {
          workflow: workflow.name,
          job: job.id,
          restoreStep: restore.name,
          restoreKey,
          laterSaveKeys: saves.filter((save) => save.index > restore.index).map((save) => save.with.key).filter((key) => typeof key === "string"),
        },
      });
    }
  }
  return detections;
}

function dockerfileCacheOrder(workflow: DepotWorkflow, repository: RepositoryContext): Detection[] {
  const buildSteps = workflow.jobs.flatMap((job) => job.steps.filter((step) => isBuildAction(step.uses)).map((step) => ({ job, step })));
  if (buildSteps.length === 0) {
    return [];
  }

  const detections: Detection[] = [];
  for (const dockerfile of repository.dockerfiles) {
    const issue = broadCopyBeforeDependencyInstall(dockerfile.source);
    if (issue === undefined) {
      continue;
    }
    detections.push({
      ruleId: "depotci.build.cache-order",
      subject: dockerfile.path,
      groupKey: `depotci.build.cache-order:${dockerfile.path}`,
      file: dockerfile.path,
      line: issue.copyLine,
      snippet: issue.copySnippet,
      label: `${dockerfile.path} copies the full context before dependency installation`,
      data: {
        workflow: workflow.name,
        buildJobs: [...new Set(buildSteps.map(({ job }) => job.id))].sort(),
        dockerfile: dockerfile.path,
        dependencyInstallLine: issue.installLine,
      },
    });
  }
  return detections;
}

function cacheKeyWeaknesses(job: WorkflowJob, step: WorkflowStep, key: string): string[] {
  const lower = key.toLowerCase();
  const reasons: string[] = [];
  const manager = packageManagerInstall(job);
  const hasFallbackKeys = typeof step.with["restore-keys"] === "string" && step.with["restore-keys"].trim().length > 0;
  if (/github\.sha|github\.event\.after|commit(?:[_-]?sha)?/.test(lower) && (manager !== undefined || hasFallbackKeys)) {
    reasons.push("the full commit identity prevents reuse across commits");
  }
  if (manager !== undefined && !/hashfiles\s*\(/i.test(key)) {
    reasons.push("the dependency cache key does not include a lockfile digest");
  }
  const compatibilitySensitive = /matrix\.(?:arch|architecture|platform|os)|\b(?:arch|architecture|platform)\b/i.test(expressionText(job.raw.strategy));
  if (compatibilitySensitive && !/(?:runner\.(?:os|arch)|matrix\.(?:os|arch|architecture|platform))/i.test(key)) {
    reasons.push("the key omits the operating-system or architecture compatibility boundary");
  }
  const stripped = key.replace(/\$\{\{[^}]+\}\}/g, "").replace(/[-_.]/g, "").trim();
  if (!/hashfiles\s*\(/i.test(key) && stripped.length < 5 && !reasons.some((reason) => reason.includes("lockfile"))) {
    reasons.push("the key is effectively constant and does not track build inputs");
  }
  return [...new Set(reasons)];
}

function isCacheStep(step: WorkflowStep): boolean {
  return /actions\/cache(?:\/(?:restore|save))?@/i.test(step.uses ?? "");
}

function packageManagerInstall(job: WorkflowJob): "npm" | "pnpm" | "yarn" | "python" | "cargo" | undefined {
  const commands = job.steps.map((step) => step.run ?? "").join("\n");
  if (/\bnpm\s+(?:ci|install)\b/i.test(commands)) return "npm";
  if (/\bpnpm\s+install\b/i.test(commands)) return "pnpm";
  if (/\byarn\s+(?:install|--frozen-lockfile)\b/i.test(commands)) return "yarn";
  if (/\b(?:pip|pip3|python\s+-m\s+pip)\s+install\b/i.test(commands)) return "python";
  if (/\bcargo\s+(?:fetch|build|test)\b/i.test(commands)) return "cargo";
  return undefined;
}

function installPattern(manager: "npm" | "pnpm" | "yarn" | "python" | "cargo"): RegExp {
  return ({
    npm: /\bnpm\s+(?:ci|install)\b/i,
    pnpm: /\bpnpm\s+install\b/i,
    yarn: /\byarn\s+(?:install|--frozen-lockfile)\b/i,
    python: /\b(?:pip|pip3|python\s+-m\s+pip)\s+install\b/i,
    cargo: /\bcargo\s+(?:fetch|build|test)\b/i,
  })[manager];
}

function lockfilesForManager(lockfiles: string[], manager: "npm" | "pnpm" | "yarn" | "python" | "cargo"): string[] {
  const pattern = ({
    npm: /(?:^|\/)package-lock\.json$/,
    pnpm: /(?:^|\/)pnpm-lock\.yaml$/,
    yarn: /(?:^|\/)yarn\.lock$/,
    python: /(?:^|\/)(?:poetry\.lock|Pipfile\.lock|requirements[^/]*\.txt)$/,
    cargo: /(?:^|\/)Cargo\.lock$/,
  })[manager];
  return lockfiles.filter((path) => pattern.test(path));
}

function keysCorrespond(restore: string | undefined, save: string | undefined): boolean {
  return restore !== undefined && save !== undefined && restore.trim() === save.trim();
}

function broadCopyBeforeDependencyInstall(source: string): { copyLine: number; copySnippet: string; installLine: number } | undefined {
  const lines = source.split(/\r?\n/);
  let broadCopy: number | undefined;
  for (const [index, line] of lines.entries()) {
    const normalized = line.trim();
    if (/^(?:COPY|ADD)\s+(?:--[^\s]+\s+)*\.?\/?\s+\.?\/?(?:\s|$)/i.test(normalized) || /^(?:COPY|ADD)\s+(?:--[^\s]+\s+)*\.\s+\S+/i.test(normalized)) {
      broadCopy ??= index;
    }
    if (broadCopy !== undefined && /^RUN\s+.*\b(?:npm\s+(?:ci|install)|pnpm\s+install|yarn\s+install|go\s+mod\s+download|cargo\s+(?:fetch|build)|pip\s+install)\b/i.test(normalized)) {
      return { copyLine: broadCopy + 1, copySnippet: lines[broadCopy]?.trim() ?? "", installLine: index + 1 };
    }
  }
  return undefined;
}
