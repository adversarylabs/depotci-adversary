import { Severity } from "@adversarylabs/sdk";
import { type DepotWorkflow, type WorkflowJob, type WorkflowStep } from "../model.js";
import { isReleaseJob, permissionWrites, secretNames, stepText } from "./helpers.js";
import { type Detection } from "./types.js";

const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/i;
const DELIVERY_ACTION = /\b(?:auth|attest|build-push|credential|deploy|login|publish|release|sign)\b/i;

interface PinnedActionContract {
  action: string;
  ref: string;
  release: string;
  inputs: readonly string[];
  metadataUrl: string;
}

const PINNED_ACTION_CONTRACTS: readonly PinnedActionContract[] = [{
  action: "depot/cache-mount",
  ref: "c4ccf77f90f7fa7df6a002813c0b13f6a5943063",
  release: "v1.2.1",
  inputs: ["debug", "name", "path"],
  metadataUrl: "https://github.com/depot/cache-mount/blob/v1.2.1/action.yml",
}];

type AuthorityTier = "privileged-delivery" | "privileged" | "delivery" | "routine";

interface ActionAuthority {
  tier: AuthorityTier;
  releaseContext: boolean;
  writePermissions: string[];
  secretNames: string[];
  reasons: string[];
}

export function analyzeActions(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];

  for (const job of workflow.jobs) {
    if (job.uses !== undefined) {
      const parsed = parseExternalReference(job.uses);
      if (parsed !== undefined && !FULL_COMMIT_SHA.test(parsed.ref)) {
        detections.push(unpinnedDetection(
          workflow,
          job,
          undefined,
          job.id,
          job.fieldLocations.uses ?? job.location,
          parsed.ownerRepository,
          parsed.ref,
        ));
      }
    }

    for (const step of job.steps) {
      if (step.uses !== undefined) {
        const parsed = parseExternalReference(step.uses);
        if (parsed !== undefined && !FULL_COMMIT_SHA.test(parsed.ref)) {
          detections.push(unpinnedDetection(
            workflow,
            job,
            step,
            `${job.id}/${step.name}`,
            step.fieldLocations.uses ?? step.location,
            parsed.ownerRepository,
            parsed.ref,
          ));
        }
        if (parsed !== undefined) {
          detections.push(...unsupportedActionInputs(workflow, job, step, parsed.path, parsed.ref));
        }
      }

      detections.push(...mutableRunInputs(workflow, job.id, step.name, step.run, step.location.line, step.location.snippet));
    }
  }

  return detections;
}

function parseExternalReference(uses: string): { ownerRepository: string; path: string; ref: string } | undefined {
  const value = uses.trim();
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("docker://")) {
    return undefined;
  }
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) {
    return undefined;
  }
  const path = value.slice(0, at);
  const parts = path.split("/");
  if (parts.length < 2) {
    return undefined;
  }
  return { ownerRepository: `${parts[0]}/${parts[1]}`, path, ref: value.slice(at + 1) };
}

function unsupportedActionInputs(
  workflow: DepotWorkflow,
  job: WorkflowJob,
  step: WorkflowStep,
  action: string,
  ref: string,
): Detection[] {
  const contract = PINNED_ACTION_CONTRACTS.find((candidate) =>
    candidate.action.toLowerCase() === action.toLowerCase() && candidate.ref.toLowerCase() === ref.toLowerCase());
  if (contract === undefined) {
    return [];
  }

  const supported = new Set(contract.inputs.map((input) => input.toLowerCase()));
  return Object.entries(step.inputLocations)
    .filter(([input]) => !supported.has(input.toLowerCase()))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([input, location]) => ({
      ruleId: "depotci.action.unsupported-input",
      subject: `${contract.action}:${input}`,
      groupKey: `depotci.action.unsupported-input:${contract.action}`,
      file: workflow.path,
      line: location.line,
      snippet: location.snippet,
      label: `${job.id}/${step.name} passes unsupported input ${input} to ${contract.action}@${contract.release}`,
      data: {
        workflow: workflow.name,
        job: job.id,
        step: step.name,
        action: contract.action,
        reference: ref,
        release: contract.release,
        input,
        supportedInputs: contract.inputs,
        contractSource: contract.metadataUrl,
      },
      locality: { kind: "direct" as const, anchors: [location.line] },
    }));
}

function unpinnedDetection(
  workflow: DepotWorkflow,
  job: WorkflowJob,
  step: WorkflowStep | undefined,
  subject: string,
  location: { line: number; snippet: string },
  ownerRepository: string,
  ref: string,
): Detection {
  const authority = actionAuthority(workflow, job, step, ownerRepository);
  return {
    ruleId: "depotci.action.unpinned",
    subject: ownerRepository,
    groupKey: `depotci.action.unpinned:${authority.tier}`,
    severity: authority.tier === "privileged-delivery" || authority.tier === "privileged"
      ? Severity.High
      : authority.tier === "delivery"
        ? Severity.Medium
        : Severity.Low,
    file: workflow.path,
    line: location.line,
    snippet: location.snippet,
    label: `${subject} uses ${ownerRepository}@${ref}`,
    data: {
      workflow: workflow.name,
      job: job.id,
      step: step?.name,
      action: ownerRepository,
      reference: ref,
      referenceType: classifyReference(ref),
      authorityTier: authority.tier,
      releaseContext: authority.releaseContext,
      writePermissions: authority.writePermissions,
      secretNames: authority.secretNames,
      authorityReasons: authority.reasons,
    },
    ...(authority.tier === "routine"
      ? { locality: { kind: "direct" as const, anchors: [location.line] } }
      : {}),
  };
}

function actionAuthority(
  workflow: DepotWorkflow,
  job: WorkflowJob,
  step: WorkflowStep | undefined,
  ownerRepository: string,
): ActionAuthority {
  const writePermissions = permissionWrites(job.permissions ?? workflow.permissions);
  const credentials = secretNames({
    workflow: workflow.env,
    job: job.env,
    action: step?.raw ?? job.raw,
  });
  const releaseContext = DELIVERY_ACTION.test(`${workflow.name} ${workflow.path}`) || isReleaseJob(job) || DELIVERY_ACTION.test(ownerRepository) || (step !== undefined && DELIVERY_ACTION.test(stepText(step)));
  const reasons = [
    ...(writePermissions.length > 0
      ? [`This action executes with repository write permissions (${writePermissions.join(", ")}).`]
      : []),
    ...(credentials.length > 0
      ? [`This action receives publishing or deployment credentials (${credentials.join(", ")}).`]
      : []),
    ...(releaseContext ? ["This action runs in a release, publishing, signing, or deployment path."] : []),
  ];
  const tier: AuthorityTier = writePermissions.length > 0 || credentials.length > 0
    ? (releaseContext ? "privileged-delivery" : "privileged")
    : releaseContext
      ? "delivery"
      : "routine";
  return { tier, releaseContext, writePermissions, secretNames: credentials, reasons };
}

function classifyReference(ref: string): "latest" | "version-tag" | "branch-or-tag" {
  if (ref.toLowerCase() === "latest") {
    return "latest";
  }
  if (/^v?\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?$/.test(ref)) {
    return "version-tag";
  }
  return "branch-or-tag";
}

function mutableRunInputs(
  workflow: DepotWorkflow,
  job: string,
  step: string,
  run: string | undefined,
  line: number,
  snippet: string,
): Detection[] {
  if (run === undefined) {
    return [];
  }
  const executed = executableShellLines(run);
  const reasons: string[] = [];
  if (executed.some((line) => isExecutedCommand(line, "(?:curl|wget)") && /(?:raw\.githubusercontent\.com|github\.com\/[^\s]+\/raw\/)(?:[^\s]+\/)?(?:main|master|HEAD)\b/i.test(line))) {
    reasons.push("script is downloaded from a mutable branch");
  }
  if (executed.some((line) => isExecutedCommand(line, "(?:curl|wget)") && /\|\s*(?:sudo\s+)?(?:ba)?sh\b/i.test(line))) {
    reasons.push("downloaded content is executed directly without an integrity check");
  }
  if (executed.some((line) => isExecutedCommand(line, "docker") && /\bdocker\s+(?:pull|run)\s+[^\s]+:latest\b/i.test(line))) {
    reasons.push("container image uses the mutable latest tag");
  }
  if (reasons.length === 0) {
    return [];
  }
  return [{
    ruleId: "depotci.build.mutable-input",
    subject: `${workflow.path}:${job}`,
    groupKey: `depotci.build.mutable-input:${workflow.path}`,
    file: workflow.path,
    line,
    snippet,
    label: `${job}/${step} uses a mutable external build input`,
    data: { workflow: workflow.name, job, step, reasons },
  }];
}

function executableShellLines(run: string): string[] {
  const lines = run.split(/\r?\n/);
  const physicalLines: string[] = [];
  let heredocTerminator: string | undefined;

  for (const line of lines) {
    if (heredocTerminator !== undefined) {
      if (line.trim().replace(/^\t+/, "") === heredocTerminator) {
        heredocTerminator = undefined;
      }
      continue;
    }

    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      continue;
    }
    physicalLines.push(trimmed);
    const heredoc = trimmed.match(/<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?/);
    heredocTerminator = heredoc?.[1];
  }
  return joinShellContinuations(physicalLines);
}

function joinShellContinuations(lines: string[]): string[] {
  const logicalLines: string[] = [];
  let pending = "";
  for (const line of lines) {
    const { continued, fragment } = shellContinuation(line);
    pending = pending.length === 0 ? fragment : `${pending} ${fragment.trimStart()}`;
    if (!continued) {
      logicalLines.push(pending);
      pending = "";
    }
  }
  if (pending.length > 0) {
    logicalLines.push(pending);
  }
  return logicalLines;
}

function shellContinuation(line: string): { continued: boolean; fragment: string } {
  const trailing = line.match(/(\\+)\s*$/);
  if (trailing === null || trailing[1].length % 2 === 0 || trailing.index === undefined) {
    return { continued: false, fragment: line };
  }
  return {
    continued: true,
    fragment: `${line.slice(0, trailing.index)}${trailing[1].slice(0, -1)}`.trimEnd(),
  };
}

function isExecutedCommand(line: string, command: string): boolean {
  return new RegExp(`(?:^|&&\\s*|\\|\\|\\s*|[;|]\\s*|\\$\\(\\s*|\\b(?:then|do)\\s+)(?:sudo\\s+)?${command}\\b`, "i").test(line);
}
