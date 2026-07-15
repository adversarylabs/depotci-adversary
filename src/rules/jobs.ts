import { type DepotWorkflow, type WorkflowJob, type WorkflowStep } from "../model.js";
import {
  allJobReferences,
  directAndTransitiveNeeds,
  hasCacheUse,
  isExpensiveWorkflow,
  isImportantStep,
  isLongRunningJob,
  isPullRequestWorkflow,
  isReleaseJob,
} from "./helpers.js";
import { type Detection } from "./types.js";

export function analyzeJobs(workflow: DepotWorkflow): Detection[] {
  return [
    ...missingTimeouts(workflow),
    ...dependencyStructure(workflow),
    ...failureMasking(workflow),
    ...releaseGates(workflow),
    ...missingConcurrency(workflow),
    ...redundantWork(workflow),
  ];
}

function missingTimeouts(workflow: DepotWorkflow): Detection[] {
  return workflow.jobs
    .filter((job) => job.timeoutMinutes === undefined && isLongRunningJob(job))
    .map((job) => ({
      ruleId: "depotci.job.missing-timeout",
      subject: job.id,
      groupKey: "depotci.job.missing-timeout:jobs",
      file: workflow.path,
      line: job.location.line,
      snippet: job.location.snippet,
      label: `${job.id} job has no timeout-minutes`,
      data: { workflow: workflow.name, job: job.id, runsOn: job.runsOn, longRunningSignals: longRunningSignals(job) },
    }));
}

function dependencyStructure(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  const jobIds = new Set(workflow.jobs.map((job) => job.id));

  for (const job of workflow.jobs) {
    for (const dependency of job.needs) {
      if (!jobIds.has(dependency)) {
        detections.push(dependencyDetection(workflow, job, `declares missing job ${dependency}`, { dependency, issue: "missing-job" }));
      }
    }

    const references = [...new Set(allJobReferences(job.raw))].sort();
    for (const producer of references) {
      if (jobIds.has(producer) && !job.needs.includes(producer)) {
        detections.push(dependencyDetection(workflow, job, `reads needs.${producer} without directly depending on ${producer}`, {
          producer,
          issue: "undeclared-output-dependency",
        }));
      }
    }
  }

  const artifactProducers = findArtifactProducers(workflow);
  for (const job of workflow.jobs) {
    const ancestors = directAndTransitiveNeeds(workflow, job);
    for (const step of job.steps.filter((candidate) => /actions\/download-artifact@/i.test(candidate.uses ?? ""))) {
      const artifactName = typeof step.with.name === "string" ? step.with.name : undefined;
      if (artifactName === undefined) {
        continue;
      }
      const producers = artifactProducers.get(artifactName) ?? [];
      if (producers.length === 1 && producers[0] !== job.id && !ancestors.has(producers[0] ?? "")) {
        detections.push({
          ruleId: "depotci.job.dependency-structure",
          subject: job.id,
          groupKey: `depotci.job.dependency-structure:${workflow.path}`,
          file: workflow.path,
          line: step.location.line,
          snippet: step.location.snippet,
          label: `${job.id} downloads ${artifactName} without depending on its producer`,
          data: { workflow: workflow.name, consumer: job.id, producer: producers[0], artifact: artifactName, issue: "artifact-without-dependency" },
        });
      }
    }
  }

  return detections;
}

function failureMasking(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  for (const job of workflow.jobs) {
    for (const step of job.steps) {
      if (!isImportantStep(step)) {
        continue;
      }
      const patterns: string[] = [];
      if (step.continueOnError) {
        patterns.push("continue-on-error is true");
      }
      if (/(?:^|[;\n]\s*)set\s+\+e(?:\s|$)/m.test(step.run ?? "")) {
        patterns.push("shell error propagation is disabled with set +e");
      }
      if (/(?:^|[;&|]\s*|\n\s*)[^#\n]+\s+\|\|\s+(?:true|:)(?:\s|$)/m.test(step.run ?? "")) {
        patterns.push("command failure is discarded with || true");
      }
      if (patterns.length > 0) {
        detections.push({
          ruleId: "depotci.step.failure-masked",
          subject: `${job.id}/${step.name}`,
          groupKey: `depotci.step.failure-masked:${workflow.path}`,
          file: workflow.path,
          line: step.location.line,
          snippet: step.location.snippet,
          label: `${job.id}/${step.name} can continue after failure`,
          data: { workflow: workflow.name, job: job.id, step: step.name, patterns },
        });
      }
    }
  }
  return detections;
}

function releaseGates(workflow: DepotWorkflow): Detection[] {
  const detections: Detection[] = [];
  for (const job of workflow.jobs.filter(isReleaseJob)) {
    const ancestors = directAndTransitiveNeeds(workflow, job);
    const hasValidationAncestor = workflow.jobs.some((candidate) => ancestors.has(candidate.id) && isValidationBoundary(candidate));
    const releaseIndex = job.steps.findIndex(isReleaseStep);
    const hasEarlierValidation = releaseIndex > 0 && job.steps.slice(0, releaseIndex).some(isValidationStep);
    if (!hasValidationAncestor && !hasEarlierValidation) {
      const step = releaseIndex >= 0 ? job.steps[releaseIndex] : undefined;
      detections.push({
        ruleId: "depotci.release.missing-gate",
        subject: job.id,
        groupKey: `depotci.release.missing-gate:${workflow.path}`,
        file: workflow.path,
        line: step?.location.line ?? job.location.line,
        snippet: step?.location.snippet ?? job.location.snippet,
        label: `${job.id} can publish or deploy without a validation dependency`,
        data: { workflow: workflow.name, job: job.id, declaredNeeds: job.needs, releaseStep: step?.name, validationAncestors: [] },
      });
    }
  }
  return detections;
}

function missingConcurrency(workflow: DepotWorkflow): Detection[] {
  if (!isPullRequestWorkflow(workflow) || !isExpensiveWorkflow(workflow) || workflow.concurrency !== undefined) {
    return [];
  }
  return [{
    ruleId: "depotci.workflow.concurrency",
    subject: workflow.path,
    groupKey: "depotci.workflow.concurrency:pull-requests",
    file: workflow.path,
    line: workflow.location.line,
    snippet: workflow.location.snippet,
    label: `${workflow.name} handles pull requests without concurrency cancellation`,
    data: {
      workflow: workflow.name,
      events: [...workflow.events].sort(),
      expensiveJobs: workflow.jobs.filter(isLongRunningJob).map((job) => job.id),
    },
  }];
}

function redundantWork(workflow: DepotWorkflow): Detection[] {
  const commands = new Map<string, Array<{ job: WorkflowJob; step: WorkflowStep }>>();
  for (const job of workflow.jobs) {
    if (hasCacheUse(job)) {
      continue;
    }
    for (const step of job.steps) {
      const command = normalizeExpensiveCommand(step.run);
      if (command !== undefined) {
        commands.set(command, [...(commands.get(command) ?? []), { job, step }]);
      }
    }
  }

  const detections: Detection[] = [];
  for (const [command, occurrences] of [...commands.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const jobs = [...new Set(occurrences.map((occurrence) => occurrence.job.id))];
    if (jobs.length < 3) {
      continue;
    }
    const first = occurrences[0];
    if (first === undefined) {
      continue;
    }
    detections.push({
      ruleId: "depotci.workflow.redundant-work",
      subject: command,
      groupKey: `depotci.workflow.redundant-work:${workflow.path}`,
      file: workflow.path,
      line: first.step.location.line,
      snippet: first.step.location.snippet,
      label: `${command} is repeated in ${jobs.length} jobs`,
      data: { workflow: workflow.name, command, jobs: jobs.sort(), cacheDetected: false },
    });
  }
  return detections;
}

function dependencyDetection(workflow: DepotWorkflow, job: WorkflowJob, label: string, data: Record<string, unknown>): Detection {
  return {
    ruleId: "depotci.job.dependency-structure",
    subject: job.id,
    groupKey: `depotci.job.dependency-structure:${workflow.path}`,
    file: workflow.path,
    line: job.location.line,
    snippet: job.location.snippet,
    label: `${job.id} ${label}`,
    data: { workflow: workflow.name, job: job.id, declaredNeeds: job.needs, ...data },
  };
}

function findArtifactProducers(workflow: DepotWorkflow): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const job of workflow.jobs) {
    for (const step of job.steps.filter((candidate) => /actions\/upload-artifact@/i.test(candidate.uses ?? ""))) {
      const name = typeof step.with.name === "string" ? step.with.name : undefined;
      if (name !== undefined) {
        result.set(name, [...(result.get(name) ?? []), job.id]);
      }
    }
  }
  return result;
}

function longRunningSignals(job: WorkflowJob): string[] {
  return job.steps
    .filter(isImportantStep)
    .map((step) => step.name)
    .slice(0, 5);
}

function isReleaseStep(step: WorkflowStep): boolean {
  return /\b(?:publish|release|deploy|docker push|npm publish|cargo publish|twine upload|gh release|kubectl|helm upgrade)\b/i.test(`${step.name} ${step.uses ?? ""} ${step.run ?? ""}`);
}

function isValidationStep(step: WorkflowStep): boolean {
  return /\b(?:build|test|lint|check|validate|verify|scan|audit|quality|coverage|sign|attest)\b/i.test(`${step.name} ${step.uses ?? ""} ${step.run ?? ""}`);
}

function isValidationBoundary(job: WorkflowJob): boolean {
  return /\b(?:build|test|lint|check|validate|verify|scan|audit|quality|coverage)\b/i.test(`${job.id} ${job.name}`) || job.steps.some(isValidationStep);
}

function normalizeExpensiveCommand(run: string | undefined): string | undefined {
  if (run === undefined) {
    return undefined;
  }
  const lines = run.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith("#"));
  const expensive = lines.find((line) => /^(?:npm ci|pnpm install(?:\s+--frozen-lockfile)?|yarn install(?:\s+--frozen-lockfile)?|go mod download|cargo fetch|pip install\s+-r\s+\S+|docker build\b)/i.test(line));
  return expensive?.replace(/\s+/g, " ").toLowerCase();
}
