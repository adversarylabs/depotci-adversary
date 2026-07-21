import { type RuleContext } from "@adversarylabs/sdk";
import { defaultSeverity } from "./rules/definitions.js";
import { type Detection } from "./rules/types.js";

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

export function reportPrimaryOpportunities(ctx: RuleContext, detections: Detection[]): void {
  const opportunities = primaryOpportunities(detections);
  if (opportunities.length === 0) {
    return;
  }
  ctx.review.observe({
    key: "depotci.primary-opportunities",
    summary: `Primary opportunities\n${opportunities.map((opportunity, index) => `${index + 1}. ${opportunity}`).join("\n")}`,
  });
}

export function primaryOpportunities(detections: Detection[]): string[] {
  const byRemediation = new Map<string, { opportunity: string; severity: keyof typeof SEVERITY_RANK; impact: number }>();
  for (const detection of detections) {
    const opportunity = opportunityFor(detection);
    if (opportunity === undefined) {
      continue;
    }
    const severity = detection.severity ?? defaultSeverity(detection.ruleId);
    const impact = operationalPriority(detection);
    const key = detection.ruleId === "depotci.action.unpinned" ? detection.groupKey : detection.ruleId;
    const current = byRemediation.get(key);
    if (current === undefined || SEVERITY_RANK[severity] > SEVERITY_RANK[current.severity] || (severity === current.severity && impact > current.impact)) {
      byRemediation.set(key, { opportunity, severity, impact });
    }
  }
  return [...byRemediation.entries()]
    .sort(([leftKey, left], [rightKey, right]) => SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity] || right.impact - left.impact || leftKey.localeCompare(rightKey))
    .slice(0, 5)
    .map(([, value]) => value.opportunity);
}

export function materialAssessment(detections: Detection[]): string {
  if (detections.some((detection) => detection.ruleId === "depotci.pull-request.untrusted-code")) {
    return "A trusted pull-request workflow executes contributor-controlled code while credentials, write access, caches, or privileged Depot infrastructure remain available. That trust-boundary problem dominates the review; the remaining findings are secondary hardening.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.secret.scope")) {
    return "The workflow makes credentials available beyond the steps that require them. Narrowing that credential boundary matters more than the remaining reliability and efficiency improvements.";
  }
  const privilegedActions = detections.filter((detection) => detection.ruleId === "depotci.action.unpinned" && detection.data.authorityTier === "privileged-delivery");
  if (privilegedActions.length > 0) {
    const permissions = uniqueStrings(privilegedActions.flatMap((detection) => stringArray(detection.data.writePermissions)));
    const credentials = uniqueStrings(privilegedActions.flatMap((detection) => stringArray(detection.data.secretNames)));
    const authority = [
      ...(permissions.length > 0 ? [`repository write permissions (${permissions.join(", ")})`] : []),
      ...(credentials.length > 0 ? [`publishing or deployment credentials (${credentials.join(", ")})`] : []),
    ];
    const authorityText = authority.length === 0 ? "delivery authority" : authority.join(" and ");
    return `The workflows are generally decomposed into understandable jobs, but release and publishing paths rely on mutable third-party actions that execute with ${authorityText}. The remaining findings are primarily operational hardening and should be prioritized after that supply-chain boundary.`;
  }
  const elevatedActions = detections.filter((detection) => detection.ruleId === "depotci.action.unpinned" && detection.data.authorityTier === "privileged");
  if (elevatedActions.length > 0) {
    const permissions = uniqueStrings(elevatedActions.flatMap((detection) => stringArray(detection.data.writePermissions)));
    const credentials = uniqueStrings(elevatedActions.flatMap((detection) => stringArray(detection.data.secretNames)));
    const authority = [
      ...(permissions.length > 0 ? [`repository write permissions (${permissions.join(", ")})`] : []),
      ...(credentials.length > 0 ? [`credentials (${credentials.join(", ")})`] : []),
    ];
    return `Mutable third-party actions execute with ${authority.join(" and ") || "elevated workflow authority"}. That supply-chain boundary is the first issue to fix; the remaining findings are lower-priority operational hardening.`;
  }
  if (detections.some((detection) => detection.ruleId === "depotci.release.missing-gate")) {
    return "Publishing or deployment can proceed without consuming the workflow's validation boundary. The remaining findings concern reproducibility and operational hardening, but release gating should be fixed first.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.build.mutable-input")) {
    return "CI executes remote code or mutable images without an immutable version and integrity boundary. That supply-chain input should be fixed before the remaining reliability and efficiency improvements.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.permissions.broad")) {
    return "Repository write authority is available to more workflow code than the delivery path requires. Narrowing those token permissions is the primary hardening step; the remaining findings have lower operational impact.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.step.failure-masked")) {
    return "A required build, validation, or delivery command can fail while the workflow still reports success. Restoring truthful failure propagation matters more than the remaining operational hardening.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.job.dependency-structure")) {
    return "The declared job graph does not reliably connect producers to the jobs that consume their outputs or artifacts. Repairing that execution order is the prerequisite for the remaining workflow improvements.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.workflow.parse-error")) {
    return "One or more workflow files could not be parsed, so their execution behavior and security boundaries could not be reviewed completely. Fixing the workflow structure is the prerequisite for the remaining review.";
  }
  if (detections.some((detection) => detection.ruleId === "depotci.action.unpinned" && detection.data.authorityTier === "delivery")) {
    return "Release or publishing paths depend on mutable third-party action references, so identical repository commits can execute different delivery code later. The remaining findings are lower-priority operational hardening.";
  }
  return "The workflows are usable, but the highest-impact finding affects their correctness or production reliability. The remaining findings are lower-priority operational hardening.";
}

function opportunityFor(detection: Detection): string | undefined {
  if (detection.ruleId === "depotci.action.unpinned") {
    if (detection.data.authorityTier === "privileged-delivery") {
      return "Pin release-critical GitHub Actions by full commit SHA.";
    }
    if (detection.data.authorityTier === "privileged") {
      return "Pin GitHub Actions that execute with elevated authority by full commit SHA.";
    }
    if (detection.data.authorityTier === "delivery") {
      return "Pin delivery-related GitHub Actions by full commit SHA.";
    }
    return "Establish a repository-wide GitHub Action pinning policy.";
  }
  const opportunities: Partial<Record<Detection["ruleId"], string>> = {
    "depotci.workflow.parse-error": "Fix malformed workflow files and rerun the review.",
    "depotci.job.missing-timeout": "Add explicit timeout-minutes to long-running jobs.",
    "depotci.job.dependency-structure": "Repair producer-consumer job dependencies.",
    "depotci.cache.unstable-key": "Make cache keys track stable compatibility inputs and lockfiles.",
    "depotci.cache.lifecycle": "Pair cache restores with an intentional save path.",
    "depotci.build.cache-order": "Reorder Docker build inputs to preserve dependency layers.",
    "depotci.secret.scope": "Restrict credentials to the exact steps that consume them.",
    "depotci.pull-request.untrusted-code": "Separate untrusted pull-request execution from trusted capabilities.",
    "depotci.permissions.broad": "Narrow write permissions to the delivery jobs that require them.",
    "depotci.step.failure-masked": "Allow required validation and delivery failures to fail the workflow.",
    "depotci.release.missing-gate": "Gate publishing and deployment on completed validation.",
    "depotci.workflow.concurrency": "Cancel superseded pull-request workflow runs.",
    "depotci.build.mutable-input": "Pin and verify remote code executed by CI.",
  };
  return opportunities[detection.ruleId];
}

function operationalPriority(detection: Detection): number {
  if (detection.ruleId === "depotci.action.unpinned") {
    return detection.data.authorityTier === "privileged-delivery"
      ? 90
      : detection.data.authorityTier === "privileged"
        ? 85
        : detection.data.authorityTier === "delivery"
          ? 65
          : 20;
  }
  const priorities: Partial<Record<Detection["ruleId"], number>> = {
    "depotci.pull-request.untrusted-code": 100,
    "depotci.secret.scope": 95,
    "depotci.release.missing-gate": 80,
    "depotci.build.mutable-input": 75,
    "depotci.step.failure-masked": 70,
    "depotci.permissions.broad": 68,
    "depotci.job.dependency-structure": 60,
    "depotci.workflow.parse-error": 58,
    "depotci.job.missing-timeout": 40,
    "depotci.cache.lifecycle": 35,
    "depotci.cache.unstable-key": 30,
    "depotci.build.cache-order": 25,
    "depotci.workflow.concurrency": 15,
  };
  return priorities[detection.ruleId] ?? 0;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)].sort();
}
