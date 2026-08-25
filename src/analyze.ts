import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Severity, type RuleContext } from "@adversarylabs/sdk";
import { type DiscoveryResult } from "./discover.js";
import { type DepotWorkflow, type RepositoryContext, type WorkflowStep, isRecord } from "./model.js";
import { analyzeActions } from "./rules/actions.js";
import { analyzeCaching } from "./rules/cache.js";
import { defaultSeverity, observationFor } from "./rules/definitions.js";
import { hasCacheUse, isBuildAction, isLongRunningJob, isReleaseJob, secretNames, stepText } from "./rules/helpers.js";
import { analyzeJobs } from "./rules/jobs.js";
import { analyzeSecurity } from "./rules/security.js";
import { type Detection } from "./rules/types.js";
import { materialAssessment, primaryOpportunities, reportPrimaryOpportunities } from "./synthesis.js";

const execute = promisify(execFile);

export async function analyzeRepository(
  ctx: RuleContext,
  discovery: DiscoveryResult,
  repository: RepositoryContext,
): Promise<void> {
  const detections: Detection[] = discovery.failures.map((failure) => ({
    ruleId: "depotci.workflow.parse-error",
    subject: failure.path,
    groupKey: `depotci.workflow.parse-error:${failure.path}`,
    file: failure.path,
    line: failure.line,
    snippet: failure.snippet,
    label: `${failure.path}:${failure.line}${failure.column === undefined ? "" : `:${failure.column}`} could not be parsed`,
    data: { error: failure.message, column: failure.column },
  }));

  for (const workflow of discovery.workflows) {
    detections.push(...analyzeActions(workflow));
    detections.push(...analyzeJobs(workflow));
    detections.push(...analyzeCaching(workflow, repository));
    detections.push(...analyzeSecurity(workflow, ctx.repoPath));
  }

  detections.sort(compareDetections);
  const eligibleDetections = await changeLocalDetections(ctx, detections);
  for (const detection of eligibleDetections) {
    ctx.observe(observationFor(detection));
  }

  reportPositives(ctx, discovery.workflows, detections);
  reportReview(ctx, discovery, eligibleDetections);
}

async function changeLocalDetections(ctx: RuleContext, detections: Detection[]): Promise<Detection[]> {
  if (ctx.change === null || ctx.change.scanMode === "all") {
    return detections;
  }

  const changedFiles = new Set(ctx.change.changedFiles.map(normalizePath));
  const directPaths = [...new Set(detections
    .filter((detection) => detection.locality?.kind === "direct")
    .map((detection) => normalizePath(detection.file))
    .filter((path) => changedFiles.has(path)))];
  const changedLines = new Map<string, Set<number> | undefined>();
  await Promise.all(directPaths.map(async (path) => {
    changedLines.set(path, await changedLineNumbers(ctx, path));
  }));

  return detections.filter((detection) => {
    const path = normalizePath(detection.file);
    if (!changedFiles.has(path)) {
      return false;
    }
    if (detection.locality?.kind !== "direct") {
      return true;
    }
    const lines = changedLines.get(path);
    return lines === undefined || detection.locality.anchors.some((line) => lines.has(line));
  });
}

async function changedLineNumbers(ctx: RuleContext, path: string): Promise<Set<number> | undefined> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return undefined;
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) {
    args.push(head);
  }
  args.push("--", path);
  try {
    const { stdout } = await execute("git", ["-C", ctx.repoPath, ...args], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    });
    const lines = new Set<number>();
    for (const match of stdout.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
      const start = Number(match[1]);
      const count = match[2] === undefined ? 1 : Number(match[2]);
      for (let line = start; line < start + count; line += 1) {
        lines.add(line);
      }
    }
    return lines;
  } catch {
    return new Set<number>();
  }
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function reportPositives(ctx: RuleContext, workflows: DepotWorkflow[], detections: Detection[]): void {
  for (const workflow of workflows) {
    const workflowDetections = detections.filter((detection) => detection.file === workflow.path);
    const externalActions = workflow.jobs.flatMap((job) => [job.uses, ...job.steps.map((step) => step.uses)]).filter(isExternalAction);
    if (externalActions.length > 0 && !workflowDetections.some((detection) => detection.ruleId === "depotci.action.unpinned")) {
      ctx.review.positive({
        key: `depotci.actions.immutable:${workflow.path}`,
        summary: `Uses immutable commit references for all ${externalActions.length} external action invocation${externalActions.length === 1 ? "" : "s"} in ${workflow.path}.`,
        evidence: [{ file: workflow.path, line: workflow.location.line }],
      });
    }

    const longJobs = workflow.jobs.filter(isLongRunningJob);
    if (longJobs.length > 0 && longJobs.every((job) => job.timeoutMinutes !== undefined)) {
      ctx.review.positive({
        key: `depotci.jobs.timeouts:${workflow.path}`,
        summary: longJobs.length === 1
          ? `Sets an explicit timeout on the long-running job in ${workflow.path}.`
          : `Sets explicit timeouts on all ${longJobs.length} long-running jobs in ${workflow.path}.`,
        evidence: longJobs.slice(0, 5).map((job) => ({ file: workflow.path, line: job.location.line, label: `${job.id}: ${job.timeoutMinutes} minutes` })),
      });
    }

    const releaseValidation = workflow.jobs
      .filter(isReleaseJob)
      .flatMap((job) => job.steps
        .filter(isReleaseVersionValidation)
        .map((step) => ({ job: job.id, step })));
    if (releaseValidation.length > 0) {
      ctx.review.positive({
        key: `depotci.release.version-validation:${workflow.path}`,
        summary: `Validates the release version or tag before delivery in ${workflow.path}.`,
        evidence: releaseValidation.slice(0, 5).map(({ job, step }) => ({
          file: workflow.path,
          line: step.location.line,
          label: `${job}/${step.name}`,
        })),
      });
    }

    if (workflow.events.has("pull_request") && isEffectiveCancellation(workflow.concurrency)) {
      ctx.review.positive({
        key: `depotci.concurrency.cancel:${workflow.path}`,
        summary: `Cancels obsolete pull-request work in ${workflow.path} while preserving an explicit concurrency boundary.`,
        evidence: [{ file: workflow.path, line: workflow.location.line }],
      });
    }

    const dependencyJobs = workflow.jobs.filter((job) => job.needs.length > 0);
    if (dependencyJobs.length > 0 && !workflowDetections.some((detection) => detection.ruleId === "depotci.job.dependency-structure")) {
      ctx.review.positive({
        key: `depotci.dependencies.explicit:${workflow.path}`,
        summary: `Models ${dependencyJobs.length} producer-consumer job boundar${dependencyJobs.length === 1 ? "y" : "ies"} explicitly in ${workflow.path}.`,
        evidence: dependencyJobs.slice(0, 5).map((job) => ({ file: workflow.path, line: job.location.line, label: `${job.id} needs ${job.needs.join(", ")}` })),
      });
    }

    const cacheJobs = workflow.jobs.filter((job) => hasCacheUse(job) || job.steps.some((step) => isBuildAction(step.uses)));
    if (cacheJobs.length > 0 && !workflowDetections.some((detection) => detection.ruleId.startsWith("depotci.cache."))) {
      ctx.review.positive({
        key: `depotci.cache.configured:${workflow.path}`,
        summary: `Configures dependency or Depot build caching without an evident key or lifecycle defect in ${workflow.path}.`,
        evidence: cacheJobs.slice(0, 5).map((job) => ({ file: workflow.path, line: job.location.line, label: `${job.id} cache path` })),
      });
    }

    const stepScopedSecrets = workflow.jobs.flatMap((job) => job.steps.flatMap((step) => secretNames(step.env)));
    if (stepScopedSecrets.length > 0 && !workflowDetections.some((detection) => detection.ruleId === "depotci.secret.scope")) {
      ctx.review.positive({
        key: `depotci.secrets.step-scope:${workflow.path}`,
        summary: `Scopes ${new Set(stepScopedSecrets).size} referenced secret${new Set(stepScopedSecrets).size === 1 ? "" : "s"} to the steps that consume them in ${workflow.path}.`,
        evidence: [{ file: workflow.path, line: workflow.location.line }],
      });
    }
  }
}

function reportReview(ctx: RuleContext, discovery: DiscoveryResult, detections: Detection[]): void {
  if (discovery.workflows.length === 0 && discovery.failures.length === 0) {
    ctx.review.observe({
      key: "depotci.workflow.none",
      summary: "No supported Depot CI workflow structure was discovered in the configured workflow locations.",
    });
    ctx.review.assessment({ risk: "none", summary: "No supported Depot CI workflows were available for a material review." });
    ctx.review.opinion({ summary: "No Depot CI workflow opinion can be formed from this repository." });
    return;
  }

  reportPrimaryOpportunities(ctx, detections);
  const risk = highestRisk(detections);
  if (risk === "none") {
    ctx.review.assessment({
      risk,
      summary: "The reviewed Depot CI workflow is well structured and no material security, reliability, caching, or performance concerns were identified.",
    });
    ctx.review.opinion({ ship: true, summary: "I would rely on this workflow as-is." });
    return;
  }
  if (risk === "low") {
    ctx.review.assessment({
      risk,
      summary: "This is a functional Depot CI workflow with a small number of reliability or efficiency improvements available.",
    });
    ctx.review.opinion({ ship: true, summary: "I would use this workflow, with the low-risk improvements scheduled next." });
    return;
  }

  const primary = primaryOpportunities(detections)[0];
  ctx.review.assessment({
    risk,
    summary: materialAssessment(detections),
  });
  ctx.review.opinion({
    ship: false,
    summary: primary === undefined
      ? "I would address the material workflow findings before production use."
      : `I would ${trimTrailingPeriod(lowercaseFirst(primary))} before relying on these workflows for production delivery.`,
  });
}

function highestRisk(detections: Detection[]): "none" | "low" | "medium" | "high" | "critical" {
  const ranks = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
  let highest: keyof typeof ranks = "info";
  for (const detection of detections) {
    const severity = detection.severity ?? defaultSeverity(detection.ruleId);
    if (ranks[severity] > ranks[highest]) {
      highest = severity;
    }
  }
  return highest === Severity.Info ? "none" : highest;
}

function compareDetections(left: Detection, right: Detection): number {
  return left.ruleId.localeCompare(right.ruleId) || left.file.localeCompare(right.file) || left.line - right.line || left.subject.localeCompare(right.subject);
}

function isExternalAction(value: string | undefined): value is string {
  return value !== undefined && !value.startsWith("./") && !value.startsWith("../") && !value.startsWith("docker://") && value.includes("@");
}

function isEffectiveCancellation(value: unknown): boolean {
  return isRecord(value) && value["cancel-in-progress"] === true && value.group !== undefined;
}

function isReleaseVersionValidation(step: WorkflowStep): boolean {
  const value = stepText(step);
  const hasReleaseTarget = /\b(?:release|tag)\b|github\.ref(?:_name)?\b|GITHUB_REF(?:_NAME)?\b|refs\/tags\//i.test(value);
  const hasVersionSource = /\bversion\b|package\.json|Cargo\.toml|pyproject\.toml|pom\.xml/i.test(value);
  const hasComparison = /\b(?:compare|equal|match|validate|verify)(?:s|ed|ing)?\b|check-version|(?:==|!=|=~)|\btest\b|\[\[?/i.test(value);
  return hasReleaseTarget && hasVersionSource && hasComparison;
}

function lowercaseFirst(value: string): string {
  return `${value.slice(0, 1).toLowerCase()}${value.slice(1)}`;
}

function trimTrailingPeriod(value: string): string {
  return value.replace(/\.$/, "");
}
