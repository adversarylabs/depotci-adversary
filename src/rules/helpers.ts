import { type DepotWorkflow, type WorkflowJob, type WorkflowStep, expressionText, isRecord } from "../model.js";

const IMPORTANT_WORK_PATTERN = /\b(?:build|test|integration|e2e|scan|audit|publish|release|deploy|push|upload|sign|attest|migrat|wait|docker|buildx|cargo|pytest|go test|npm (?:test|publish)|pnpm (?:test|publish)|yarn (?:test|publish))\b/i;
const LONG_JOB_IDENTITY = /\b(?:build|integration|e2e|scan|audit|publish|release|deploy|coverage|race|smoke|tooling|migration)\b/i;
const LONG_STEP_LABEL = /\b(?:build|tests?|integration|e2e|scan|audit|publish|release|deploy|coverage|race|docker|buildx|migration)\b/i;
const LONG_RUN_COMMAND = /\b(?:docker\s+(?:build|push)|buildx|cargo\s+(?:build|test)|pytest|go\s+test|npm\s+(?:test|publish)|pnpm\s+(?:test|publish)|yarn\s+(?:test|publish)|make\s+(?:test|build)|kubectl|helm\s+upgrade)\b/i;
const RELEASE_PATTERN = /\b(?:publish|release|deploy|production|push(?:es|ing)?\s+(?:an?\s+)?(?:image|artifact|package)|npm publish|cargo publish|twine upload|docker push|gh release|kubectl|helm upgrade)\b/i;
const VALIDATION_PATTERN = /\b(?:test|lint|check|validate|verify|scan|audit|build|quality|coverage)\b/i;

export function jobText(job: WorkflowJob): string {
  return `${job.id} ${job.name} ${expressionText(job.raw)}`;
}

export function stepText(step: WorkflowStep): string {
  return `${step.name} ${step.uses ?? ""} ${step.run ?? ""} ${expressionText(step.with)} ${expressionText(step.env)}`;
}

export function isLongRunningJob(job: WorkflowJob): boolean {
  if (LONG_JOB_IDENTITY.test(`${job.id} ${job.name}`)) {
    return true;
  }
  return job.steps.some((step) =>
    LONG_STEP_LABEL.test(`${step.name} ${step.uses ?? ""}`) ||
    LONG_RUN_COMMAND.test(step.run ?? "") ||
    isBuildAction(step.uses));
}

export function isReleaseJob(job: WorkflowJob): boolean {
  return RELEASE_PATTERN.test(jobText(job));
}

export function isValidationJob(job: WorkflowJob): boolean {
  return VALIDATION_PATTERN.test(`${job.id} ${job.name}`) || job.steps.some((step) => VALIDATION_PATTERN.test(stepText(step)));
}

export function isImportantStep(step: WorkflowStep): boolean {
  return IMPORTANT_WORK_PATTERN.test(stepText(step));
}

export function isExpensiveWorkflow(workflow: DepotWorkflow): boolean {
  return workflow.jobs.some((job) => isLongRunningJob(job));
}

export function allJobReferences(value: unknown): string[] {
  const text = expressionText(value);
  return [...text.matchAll(/\bneeds\.([A-Za-z0-9_-]+)\b/g)].map((match) => match[1]).filter((value): value is string => value !== undefined);
}

export function secretNames(value: unknown): string[] {
  const text = expressionText(value);
  return [...new Set([...text.matchAll(/\bsecrets\.([A-Za-z0-9_]+)\b/g)].map((match) => match[1]).filter((name): name is string => name !== undefined))].sort();
}

export function hasWritePermission(value: unknown): boolean {
  if (typeof value === "string") {
    return value.toLowerCase() === "write-all";
  }
  if (!isRecord(value)) {
    return false;
  }
  return Object.values(value).some((permission) => typeof permission === "string" && permission.toLowerCase() === "write");
}

export function permissionWrites(value: unknown): string[] {
  if (typeof value === "string") {
    return value.toLowerCase() === "write-all" ? ["write-all"] : [];
  }
  if (!isRecord(value)) {
    return [];
  }
  return Object.entries(value)
    .filter(([, permission]) => typeof permission === "string" && permission.toLowerCase() === "write")
    .map(([scope]) => scope)
    .sort();
}

export function hasCacheUse(job: WorkflowJob): boolean {
  return job.steps.some((step) => {
    const uses = step.uses?.toLowerCase() ?? "";
    const withText = expressionText(step.with).toLowerCase();
    return uses.includes("cache") || ((uses.includes("setup-node") || uses.includes("setup-python") || uses.includes("setup-go")) && withText.includes("cache"));
  });
}

export function directAndTransitiveNeeds(workflow: DepotWorkflow, job: WorkflowJob): Set<string> {
  const byId = new Map(workflow.jobs.map((candidate) => [candidate.id, candidate]));
  const result = new Set<string>();
  const pending = [...job.needs];
  while (pending.length > 0) {
    const id = pending.pop();
    if (id === undefined || result.has(id)) {
      continue;
    }
    result.add(id);
    pending.push(...(byId.get(id)?.needs ?? []));
  }
  return result;
}

export function conditionAllowsPullRequest(job: WorkflowJob): boolean {
  const condition = job.if?.toLowerCase() ?? "";
  return !condition.includes("github.event_name") || condition.includes("pull_request") || condition.includes("always()");
}

export function isCheckoutOfPullRequestHead(step: WorkflowStep): boolean {
  if (!(step.uses?.toLowerCase().startsWith("actions/checkout@") ?? false)) {
    return false;
  }
  const ref = expressionText(step.with.ref).toLowerCase();
  return ref.includes("pull_request.head") || ref.includes("pull_request.head.sha") || ref.includes("github.head_ref");
}

export function executesRepositoryCodeAfterCheckout(job: WorkflowJob, checkoutIndex: number): WorkflowStep | undefined {
  return job.steps.find((step) => step.index > checkoutIndex && (step.run !== undefined || isBuildAction(step.uses)));
}

export function isBuildAction(uses: string | undefined): boolean {
  return /(?:depot|docker)\/build-push-action@/i.test(uses ?? "");
}

export function isPullRequestWorkflow(workflow: DepotWorkflow): boolean {
  return workflow.events.has("pull_request") || workflow.events.has("pull_request_target");
}
