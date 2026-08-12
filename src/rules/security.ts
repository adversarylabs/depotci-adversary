import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Confidence, Severity } from "@adversarylabs/sdk";
import { detectCiSecurityIssues, DEPOT_RULE_IDS } from "../ci-security-core.js";
import { type DepotWorkflow, type WorkflowJob, type WorkflowStep, expressionText } from "../model.js";
import {
  conditionAllowsPullRequest,
  executesRepositoryCodeAfterCheckout,
  hasWritePermission,
  isBuildAction,
  isCheckoutOfPullRequestHead,
  isReleaseJob,
  permissionWrites,
  secretNames,
} from "./helpers.js";
import { type Detection, type RuleId } from "./types.js";

export function analyzeSecurity(workflow: DepotWorkflow, repoPath = ""): Detection[] {
  return [
    ...secretScope(workflow),
    ...untrustedPullRequestExecution(workflow),
    ...broadPermissions(workflow),
    ...sharedCoreDetections(workflow, repoPath),
  ];
}

/** Shared GHA/Depot core for script-injection, self-hosted PR, and related P0s. */
function sharedCoreDetections(workflow: DepotWorkflow, repoPath: string): Detection[] {
  let source = "";
  try {
    const absolute = repoPath ? join(repoPath, workflow.path) : workflow.path;
    source = readFileSync(absolute, "utf8");
  } catch {
    return [];
  }
  const hits = detectCiSecurityIssues(workflow.path, source);
  const out: Detection[] = [];
  for (const hit of hits) {
    const mapped = DEPOT_RULE_IDS[hit.key];
    if (!mapped) continue;
    // Prefer structured analyzers for these when they already fired / cover better.
    if (
      mapped === "depotci.action.unpinned" ||
      mapped === "depotci.permissions.broad" ||
      mapped === "depotci.pull-request.untrusted-code" ||
      mapped === "depotci.secret.scope-broad"
    ) {
      continue;
    }
    const ruleId = mapped as RuleId;
    out.push({
      ruleId,
      subject: workflow.path,
      groupKey: `${ruleId}:${workflow.path}:${hit.line}`,
      file: hit.file,
      line: hit.line,
      snippet: hit.snippet,
      label: hit.label,
      data: { ...hit.data, workflow: workflow.name, sharedCore: true },
      ...(hit.key === "script-injection" || hit.key === "runs-on-expression"
        ? { locality: { kind: "direct" as const, anchors: [hit.line] } }
        : {}),
    });
  }
  return out;
}

function secretScope(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  const workflowSecrets = secretNames(workflow.env);
  if (workflowSecrets.length > 0) {
    const envLocation = workflow.fieldLocations.env ?? workflow.location;
    detections.push({
      ruleId: "depotci.secret.scope",
      subject: workflow.path,
      groupKey: `depotci.secret.scope:${workflow.path}`,
      severity: Severity.High,
      file: workflow.path,
      line: envLocation.line,
      snippet: envLocation.snippet,
      label: `${workflow.name} exposes secrets through workflow-level env`,
      data: { workflow: workflow.name, scope: "workflow", secretNames: workflowSecrets },
    });
  }

  for (const job of workflow.jobs) {
    const jobSecrets = secretNames(job.env);
    if (jobSecrets.length > 0 && job.steps.length > 1) {
      detections.push({
        ruleId: "depotci.secret.scope",
        subject: job.id,
        groupKey: `depotci.secret.scope:${workflow.path}`,
        severity: Severity.High,
        confidence: Confidence.Medium,
        file: workflow.path,
        line: job.location.line,
        snippet: job.location.snippet,
        label: `${job.id} exposes secrets through job-level env`,
        data: { workflow: workflow.name, job: job.id, scope: "job", secretNames: jobSecrets, exposedStepCount: job.steps.length },
      });
    }

    for (const step of job.steps) {
      const reasons = unsafeSecretUses(step);
      if (reasons.length === 0) {
        continue;
      }
      detections.push({
        ruleId: "depotci.secret.scope",
        subject: `${job.id}/${step.name}`,
        groupKey: `depotci.secret.scope:${workflow.path}`,
        severity: Severity.High,
        file: workflow.path,
        line: step.location.line,
        snippet: step.location.snippet,
        label: `${job.id}/${step.name} handles credentials through an unsafe channel`,
        data: { workflow: workflow.name, job: job.id, step: step.name, secretNames: secretNames(step.raw), reasons },
      });
    }
  }
  return detections;
}

function untrustedPullRequestExecution(workflow: DepotWorkflow): Detection[] {
  if (!workflow.events.has("pull_request_target")) {
    return [];
  }
  const detections: Detection[] = [];
  for (const job of workflow.jobs) {
    if (!conditionAllowsPullRequest(job)) {
      continue;
    }
    const checkout = job.steps.find(isCheckoutOfPullRequestHead);
    if (checkout === undefined) {
      continue;
    }
    const execution = executesRepositoryCodeAfterCheckout(job, checkout.index);
    if (execution === undefined) {
      continue;
    }
    const effectivePermissions = job.permissions ?? workflow.permissions;
    const secrets = secretNames({ workflowEnv: workflow.env, job: job.raw });
    const capabilities = [
      ...(secrets.length > 0 ? [`secrets: ${secrets.join(", ")}`] : []),
      ...(hasWritePermission(effectivePermissions) ? [`write permissions: ${permissionWrites(effectivePermissions).join(", ")}`] : []),
      ...(job.runsOn?.toLowerCase().includes("depot-") ? [`Depot runner: ${job.runsOn}`] : []),
      ...(job.steps.some((step) => isBuildAction(step.uses)) ? ["Depot remote build access"] : []),
      ...(job.steps.some((step) => /actions\/cache(?:\/save)?@/i.test(step.uses ?? "")) ? ["shared cache write path"] : []),
    ];
    if (capabilities.length === 0) {
      continue;
    }
    detections.push({
      ruleId: "depotci.pull-request.untrusted-code",
      subject: job.id,
      groupKey: `depotci.pull-request.untrusted-code:${workflow.path}:${job.id}`,
      severity: hasWritePermission(effectivePermissions) && secrets.length > 0 ? Severity.Critical : Severity.High,
      file: workflow.path,
      line: execution.location.line,
      snippet: execution.location.snippet,
      label: `${job.id} executes pull-request code after a trusted-context checkout`,
      data: {
        workflow: workflow.name,
        trigger: "pull_request_target",
        job: job.id,
        checkoutStep: checkout.name,
        executionStep: execution.name,
        capabilities,
      },
    });
  }
  return detections;
}

function broadPermissions(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  const globalWrites = permissionWrites(workflow.permissions);
  if (globalWrites.length > 0) {
    const unrelatedJobs = workflow.jobs.filter((job) => !isReleaseJob(job)).map((job) => job.id);
    if (workflow.permissions === "write-all" || unrelatedJobs.length > 0 || workflow.events.has("pull_request") || workflow.events.has("pull_request_target")) {
      const permissionsLocation = workflow.fieldLocations.permissions ?? workflow.location;
      detections.push({
        ruleId: "depotci.permissions.broad",
        subject: workflow.path,
        groupKey: `depotci.permissions.broad:${workflow.path}`,
        file: workflow.path,
        line: permissionsLocation.line,
        snippet: permissionsLocation.snippet,
        label: `${workflow.name} grants write permissions at workflow scope`,
        data: { workflow: workflow.name, scope: "workflow", writePermissions: globalWrites, unrelatedJobs, events: [...workflow.events].sort() },
      });
    }
  }

  for (const job of workflow.jobs) {
    const writes = permissionWrites(job.permissions);
    if (writes.length === 0) {
      continue;
    }
    if (!isReleaseJob(job) || workflow.events.has("pull_request") || workflow.events.has("pull_request_target") || writes.includes("write-all")) {
      detections.push({
        ruleId: "depotci.permissions.broad",
        subject: job.id,
        groupKey: `depotci.permissions.broad:${workflow.path}`,
        file: workflow.path,
        line: job.location.line,
        snippet: job.location.snippet,
        label: `${job.id} has write permissions outside a narrowly scoped release path`,
        data: { workflow: workflow.name, job: job.id, scope: "job", writePermissions: writes, events: [...workflow.events].sort() },
      });
    }
  }
  return detections;
}

function unsafeSecretUses(step: WorkflowStep): string[] {
  const run = step.run ?? "";
  const lowerUses = step.uses?.toLowerCase() ?? "";
  const reasons: string[] = [];
  if (/\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/.test(run)) {
    if (/(?:--(?:token|password|secret|key)|-p\b|-u\b|authorization:|docker\s+login)[^\n]*\$\{\{\s*secrets\./i.test(run)) {
      reasons.push("secret is interpolated into a command-line argument");
    }
    if (/\b(?:echo|printf)\b[^\n]*\$\{\{\s*secrets\./i.test(run)) {
      reasons.push("secret is interpolated directly into shell output");
    }
    if (/\bdocker\s+build\b[^\n]*--build-arg[^\n]*\$\{\{\s*secrets\./i.test(run)) {
      reasons.push("secret is passed to a container build as a build argument");
    }
  }
  if (isBuildAction(step.uses)) {
    const buildArgs = expressionText(step.with["build-args"] ?? step.with.build_args);
    if (secretNames(buildArgs).length > 0) {
      reasons.push("secret is passed to the remote builder through ordinary build arguments instead of a secret mount");
    }
  }
  if ((lowerUses.includes("upload-artifact") || lowerUses.includes("cache")) && secretNames(step.with).length > 0) {
    reasons.push("secret-derived data is included in an artifact or cache configuration");
  }
  return reasons;
}
