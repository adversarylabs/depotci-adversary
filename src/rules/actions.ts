import { Severity } from "@adversarylabs/sdk";
import { type DepotWorkflow } from "../model.js";
import { isReleaseJob, stepText } from "./helpers.js";
import { type Detection } from "./types.js";

const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/i;
const SENSITIVE_ACTION = /\b(?:auth|attest|build-push|credential|deploy|login|publish|release|setup-action|sign|upload)\b/i;

export function analyzeActions(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];

  for (const job of workflow.jobs) {
    if (job.uses !== undefined) {
      const parsed = parseExternalReference(job.uses);
      if (parsed !== undefined && !FULL_COMMIT_SHA.test(parsed.ref)) {
        detections.push(unpinnedDetection(workflow, job.id, job.location.line, job.location.snippet, parsed.ownerRepository, parsed.ref, isReleaseJob(job)));
      }
    }

    for (const step of job.steps) {
      if (step.uses !== undefined) {
        const parsed = parseExternalReference(step.uses);
        if (parsed !== undefined && !FULL_COMMIT_SHA.test(parsed.ref)) {
          const sensitive = isReleaseJob(job) || SENSITIVE_ACTION.test(parsed.ownerRepository) || SENSITIVE_ACTION.test(stepText(step));
          detections.push(unpinnedDetection(workflow, `${job.id}/${step.name}`, step.location.line, step.location.snippet, parsed.ownerRepository, parsed.ref, sensitive));
        }
      }

      detections.push(...mutableRunInputs(workflow, job.id, step.name, step.run, step.location.line, step.location.snippet));
    }
  }

  return detections;
}

function parseExternalReference(uses: string): { ownerRepository: string; ref: string } | undefined {
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
  return { ownerRepository: `${parts[0]}/${parts[1]}`, ref: value.slice(at + 1) };
}

function unpinnedDetection(
  workflow: DepotWorkflow,
  subject: string,
  line: number,
  snippet: string,
  ownerRepository: string,
  ref: string,
  sensitive: boolean,
): Detection {
  return {
    ruleId: "depotci.action.unpinned",
    subject: ownerRepository,
    groupKey: `depotci.action.unpinned:${ownerRepository}`,
    severity: sensitive ? Severity.Medium : Severity.Low,
    file: workflow.path,
    line,
    snippet,
    label: `${subject} uses ${ownerRepository}@${ref}`,
    data: {
      workflow: workflow.name,
      action: ownerRepository,
      reference: ref,
      referenceType: classifyReference(ref),
      sensitivePath: sensitive,
    },
  };
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
  const reasons: string[] = [];
  if (/(?:curl|wget)[^\n]*(?:raw\.githubusercontent\.com|github\.com\/[^\s]+\/raw\/)(?:[^\s]+\/)?(?:main|master|HEAD)\b/i.test(run)) {
    reasons.push("script is downloaded from a mutable branch");
  }
  if (/(?:curl|wget)[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i.test(run)) {
    reasons.push("downloaded content is executed directly without an integrity check");
  }
  if (/\bdocker\s+(?:pull|run)\s+[^\s]+:latest\b/i.test(run)) {
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
