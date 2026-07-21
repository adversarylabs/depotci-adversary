import { Adversary, Confidence, Severity, type FindingSynthesis, type ObservationInit } from "@adversarylabs/sdk";
import { type Detection, type RuleId } from "./types.js";

interface RuleLanguage {
  id: RuleId;
  category: string;
  severity: (typeof Severity)[keyof typeof Severity];
  confidence: (typeof Confidence)[keyof typeof Confidence];
  title: { singular: string; plural: string };
  summary: (count: number, subjects: string[]) => string;
  whyItMatters: string;
  impact: string;
  recommendation: string;
  complexity: "trivial" | "small" | "medium" | "large";
  tags: string[];
}

const RULES: RuleLanguage[] = [
  {
    id: "depotci.workflow.parse-error",
    category: "correctness",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Depot workflow could not be parsed", plural: "Depot workflows could not be parsed" },
    summary: (count) => `${count} Depot workflow ${count === 1 ? "file is" : "files are"} malformed or outside the supported workflow structure.`,
    whyItMatters: "A workflow that cannot be parsed cannot be executed reliably or reviewed for security and build behavior.",
    impact: "The CI configuration may fail before jobs start, and other material issues in the file remain unreviewed.",
    recommendation: "Fix the reported YAML or workflow structure, then rerun the adversary so the jobs can be reviewed.",
    complexity: "small",
    tags: ["workflow", "correctness"],
  },
  {
    id: "depotci.action.unpinned",
    category: "supply-chain",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "External action uses a mutable reference", plural: "External actions use mutable references" },
    summary: (count, subjects) => `${formatSubjects(subjects)} ${subjects.length === 1 ? "is" : "are"} referenced by mutable tag or branch in ${count} workflow location${count === 1 ? "" : "s"}.`,
    whyItMatters: "Mutable action references can change without a workflow update, weakening reproducibility and supply-chain integrity.",
    impact: "A future run can execute different third-party code even when the repository has not changed.",
    recommendation: "Pin security-sensitive and release-related actions to full commit SHAs, and use an automated dependency tool to keep pins current.",
    complexity: "small",
    tags: ["actions", "supply-chain"],
  },
  {
    id: "depotci.job.missing-timeout",
    category: "reliability",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "Long-running job has no timeout", plural: "Long-running jobs have no timeouts" },
    summary: (count) => `${count} job${count === 1 ? "" : "s"} that build, test, publish, deploy, or wait on external systems ${count === 1 ? "has" : "have"} no explicit timeout.`,
    whyItMatters: "A stalled command or unavailable dependency can consume CI capacity indefinitely or until the provider maximum timeout.",
    impact: "Hung jobs can delay feedback, occupy Depot runners, and block dependent publication or deployment work.",
    recommendation: "Set an explicit timeout that reflects the expected duration and failure mode of each long-running job.",
    complexity: "trivial",
    tags: ["reliability", "cost"],
  },
  {
    id: "depotci.job.dependency-structure",
    category: "correctness",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Job dependency graph is inconsistent", plural: "Job dependency graphs are inconsistent" },
    summary: (count) => `${count} job dependency relationship${count === 1 ? " is" : "s are"} inconsistent with declared jobs or consumed outputs.`,
    whyItMatters: "Workflow data and artifacts are only reliable when producers complete before consumers start.",
    impact: "A consumer can run without required inputs, remain permanently skipped, or fail after unrelated work has already consumed resources.",
    recommendation: "Model the producer-consumer relationship explicitly and ensure each referenced job exists and completes before its outputs or artifacts are consumed.",
    complexity: "small",
    tags: ["workflow", "dependencies"],
  },
  {
    id: "depotci.cache.unstable-key",
    category: "performance",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "Cache key is ineffective or unsafe", plural: "Cache keys are ineffective or unsafe" },
    summary: (count) => `${count} cache key${count === 1 ? " does" : "s do"} not track the inputs needed for safe, reusable cache entries.`,
    whyItMatters: "Cache keys define both reuse and isolation boundaries for dependency and build outputs.",
    impact: "The workflow can miss caches on every run, reuse incompatible data, or continue using stale dependencies after lockfiles change.",
    recommendation: "Key the cache from stable compatibility dimensions and the relevant lockfile or build-input digest; avoid commit-specific values when broader reuse is intended.",
    complexity: "small",
    tags: ["cache", "performance"],
  },
  {
    id: "depotci.cache.missing",
    category: "performance",
    severity: Severity.Info,
    confidence: Confidence.High,
    title: { singular: "Deterministic dependency work is not cached", plural: "Deterministic dependency work is not cached" },
    summary: (count) => `${count} dependency installation path${count === 1 ? " repeats" : "s repeat"} deterministic downloads without an evident package cache.`,
    whyItMatters: "Lockfile-driven dependency downloads are expensive but safely reusable when the cache follows the lockfile.",
    impact: "Every run spends avoidable time and network bandwidth downloading the same dependencies.",
    recommendation: "Enable the package-manager cache using the corresponding setup action or a narrowly scoped cache keyed by the relevant lockfile.",
    complexity: "small",
    tags: ["cache", "dependencies", "performance"],
  },
  {
    id: "depotci.cache.lifecycle",
    category: "reliability",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "Cache restore has no matching save", plural: "Cache restores have no matching saves" },
    summary: (count) => `${count} explicit cache restore${count === 1 ? " has" : "s have"} no corresponding save after outputs are produced.`,
    whyItMatters: "A restore-only cache never learns from a cold miss unless another trusted workflow populates the exact same key.",
    impact: "The workflow can appear cached while repeatedly performing the full expensive operation.",
    recommendation: "Add a matching save after the cached outputs are produced, or document and narrowly match the trusted workflow that owns cache population.",
    complexity: "small",
    tags: ["cache", "lifecycle"],
  },
  {
    id: "depotci.build.cache-order",
    category: "performance",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "Docker build ordering defeats layer reuse", plural: "Docker build ordering defeats layer reuse" },
    summary: (count) => `${count} Dockerfile build path${count === 1 ? " copies" : "s copy"} frequently changing source before dependency installation.`,
    whyItMatters: "Depot and BuildKit reuse layers only while earlier inputs remain unchanged.",
    impact: "Normal source edits invalidate dependency-install layers and force remote builders to repeat expensive deterministic work.",
    recommendation: "Copy dependency manifests and lockfiles first, install dependencies, then copy the remaining source before the build step.",
    complexity: "small",
    tags: ["depot", "buildkit", "cache"],
  },
  {
    id: "depotci.secret.scope",
    category: "secrets",
    severity: Severity.High,
    confidence: Confidence.High,
    title: { singular: "Credential is exposed beyond its required scope", plural: "Credentials are exposed beyond their required scope" },
    summary: (count) => `${count} credential use${count === 1 ? " exposes" : "s expose"} secret material through broad scope, command arguments, output, or insecure build inputs.`,
    whyItMatters: "Credentials should be available only to the operation that consumes them and should not enter logs, process arguments, or image layers.",
    impact: "Repository-controlled commands, subprocesses, build metadata, or logs may gain access to production credentials.",
    recommendation: "Scope each secret to the consuming step and pass build credentials through the platform secret mechanism or BuildKit secret mounts, never ordinary build arguments or echoed commands.",
    complexity: "small",
    tags: ["secrets", "credentials"],
  },
  {
    id: "depotci.pull-request.untrusted-code",
    category: "security",
    severity: Severity.High,
    confidence: Confidence.High,
    title: { singular: "Untrusted pull-request code can reach trusted capabilities", plural: "Untrusted pull-request code can reach trusted capabilities" },
    summary: (count) => `${count} pull_request_target execution path${count === 1 ? " checks" : "s check"} out or executes pull-request code with secrets, write access, caches, or privileged build infrastructure available.`,
    whyItMatters: "pull_request_target runs in the trusted base-repository context even when the pull request comes from an untrusted fork.",
    impact: "A contributor can modify executed code to steal credentials, poison trusted caches, publish artifacts, or control privileged Depot build resources.",
    recommendation: "Do not execute pull-request-controlled code in a trusted event context. Split untrusted validation from privileged follow-up work and pass only reviewed, immutable artifacts across that boundary.",
    complexity: "medium",
    tags: ["pull-request", "untrusted-code", "secrets"],
  },
  {
    id: "depotci.permissions.broad",
    category: "permissions",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Workflow token permissions are broader than necessary", plural: "Workflow token permissions are broader than necessary" },
    summary: (count) => `${count} workflow or job permission scope${count === 1 ? " grants" : "s grant"} broad write access outside the specific publishing or deployment operation that needs it.`,
    whyItMatters: "A compromised action or repository-controlled command inherits the token capabilities available to its job.",
    impact: "Unrelated CI work may be able to modify repository contents, packages, deployments, or identity tokens.",
    recommendation: "Use the narrowest permissions needed and scope elevated permissions to the specific job that requires them.",
    complexity: "small",
    tags: ["permissions", "least-privilege"],
  },
  {
    id: "depotci.step.failure-masked",
    category: "correctness",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Important step can fail without failing the workflow", plural: "Important steps can fail without failing the workflow" },
    summary: (count) => `${count} build, test, scan, publish, deploy, or verification step${count === 1 ? " masks" : "s mask"} command failure.`,
    whyItMatters: "A successful workflow status should mean that its required validation and delivery operations succeeded.",
    impact: "Downstream jobs or users can treat a failed build, test, scan, or deployment check as successful.",
    recommendation: "Let required commands propagate their exit status. Isolate deliberately optional diagnostics in clearly named steps that cannot gate publication or deployment.",
    complexity: "trivial",
    tags: ["failure-handling", "correctness"],
  },
  {
    id: "depotci.release.missing-gate",
    category: "release",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Publish or deploy path lacks a validation gate", plural: "Publish or deploy paths lack validation gates" },
    summary: (count) => `${count} publish or deployment job${count === 1 ? " can run" : "s can run"} without depending on or performing repository validation first.`,
    whyItMatters: "Production delivery should consume an artifact or commit that has already passed the repository's actual validation boundary.",
    impact: "A broken or untested change can be published or deployed while validation runs independently or not at all.",
    recommendation: "Make the delivery job depend on the workflow's build and test boundary, or perform those gates before the publish or deploy step in the same job.",
    complexity: "small",
    tags: ["release", "deployment", "gating"],
  },
  {
    id: "depotci.workflow.redundant-work",
    category: "performance",
    severity: Severity.Info,
    confidence: Confidence.High,
    title: { singular: "Expensive setup is repeated across jobs", plural: "Expensive setup is repeated across jobs" },
    summary: (count) => `${count} expensive deterministic command pattern${count === 1 ? " is" : "s are"} repeated across multiple jobs without an evident shared artifact or cache.`,
    whyItMatters: "Depot can parallelize work, but identical downloads and builds still consume time and runner capacity.",
    impact: "The workflow pays repeatedly for the same deterministic preparation before reaching job-specific work.",
    recommendation: "Share a validated artifact or a narrowly keyed cache when multiple jobs consume the same expensive output; keep independent work parallel.",
    complexity: "medium",
    tags: ["performance", "duplication"],
  },
  {
    id: "depotci.workflow.concurrency",
    category: "performance",
    severity: Severity.Low,
    confidence: Confidence.High,
    title: { singular: "Obsolete pull-request runs are not cancelled", plural: "Obsolete pull-request runs are not cancelled" },
    summary: (count) => `${count} pull-request workflow${count === 1 ? " performs" : "s perform"} expensive work without a cancellation policy for superseded commits.`,
    whyItMatters: "New commits make older pull-request validation runs obsolete in workflows where only the latest result is actionable.",
    impact: "Depot runners continue building and testing commits that reviewers no longer need, increasing feedback latency and cost.",
    recommendation: "Configure concurrency so newer pull-request runs cancel obsolete work while keeping release and audit runs non-cancellable.",
    complexity: "trivial",
    tags: ["concurrency", "cost", "pull-request"],
  },
  {
    id: "depotci.build.mutable-input",
    category: "supply-chain",
    severity: Severity.Medium,
    confidence: Confidence.High,
    title: { singular: "Build downloads a mutable or unverified input", plural: "Builds download mutable or unverified inputs" },
    summary: (count) => `${count} external build input${count === 1 ? " is" : "s are"} fetched from a mutable location or used without integrity verification.`,
    whyItMatters: "Remote scripts, tools, images, and unlocked packages become part of the build trust boundary.",
    impact: "The same commit can build differently later, or a compromised download endpoint can inject code into CI and release artifacts.",
    recommendation: "Fetch immutable versions and verify downloaded binaries or scripts with a trusted checksum or signature; keep release dependencies lockfile-driven.",
    complexity: "small",
    tags: ["supply-chain", "reproducibility"],
  },
];

const RULE_MAP = new Map(RULES.map((rule) => [rule.id, rule]));

export function registerDepotRules(app: Adversary): void {
  for (const rule of RULES) {
    app.defineRule({
      id: rule.id,
      category: rule.category,
      defaultSeverity: rule.severity,
      defaultConfidence: rule.confidence,
      aggregate(observations) {
        if (rule.id === "depotci.action.unpinned") {
          return synthesizeUnpinnedActions(observations);
        }
        const subjects = [...new Set(observations.map((observation) => observation.subject))].sort();
        return {
          title: observations.length === 1 ? rule.title.singular : rule.title.plural,
          category: rule.category,
          summary: rule.summary(observations.length, subjects),
          whyItMatters: rule.whyItMatters,
          impact: rule.impact,
          recommendation: rule.recommendation,
          remediation: { complexity: rule.complexity },
          tags: rule.tags,
          confidence: highestConfidence(observations, rule.confidence),
        };
      },
    });
  }
}

function synthesizeUnpinnedActions(observations: ReadonlyArray<ObservationInit>): FindingSynthesis {
  const data = observations.map(observationData);
  const tier = stringField(data[0], "authorityTier") ?? "routine";
  const releaseContext = data.some((item) => item.releaseContext === true);
  const actionCounts = new Map<string, number>();
  for (const observation of observations) {
    actionCounts.set(observation.subject, (actionCounts.get(observation.subject) ?? 0) + 1);
  }
  const affected = [...actionCounts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([action, count]) => `${action} (${count})`);
  const reasons = [...new Set(data.flatMap((item) => stringArrayField(item, "authorityReasons")))].sort();

  if (tier === "privileged-delivery" || tier === "privileged") {
    const privilegedDelivery = tier === "privileged-delivery" && releaseContext;
    return {
      title: privilegedDelivery
        ? "Release workflows execute mutable actions with production authority"
        : "Mutable actions execute with elevated workflow authority",
      category: "supply-chain",
      summary: `Mutable third-party actions execute in ${observations.length} privileged workflow location${observations.length === 1 ? "" : "s"}.\n\nAffected:\n${affected.map((item) => `- ${item}`).join("\n")}`,
      whyItMatters: `A mutable reference can replace the code executed inside an authoritative job without a repository change. ${reasons.join(" ")}`.trim(),
      impact: "Compromise of one referenced tag or branch could modify releases, repository contents, deployment state, or published artifacts using the job's existing authority.",
      recommendation: privilegedDelivery
        ? "Pin the release-critical actions to full commit SHAs first, then keep those pins current with an automated dependency update workflow."
        : "Pin actions that execute with elevated permissions or credentials to full commit SHAs, then keep those pins current with reviewed automation.",
      remediation: { complexity: "small" },
      tags: privilegedDelivery
        ? ["actions", "release", "supply-chain", "runtime"]
        : ["actions", "permissions", "supply-chain", "runtime"],
    };
  }

  if (tier === "delivery") {
    return {
      title: "Release and publishing actions use mutable references",
      category: "supply-chain",
      summary: `Delivery-related actions use mutable tags or branches in ${observations.length} workflow location${observations.length === 1 ? "" : "s"}.\n\nAffected:\n${affected.map((item) => `- ${item}`).join("\n")}`,
      whyItMatters: "Release and publishing paths should remain reproducible even when the referenced action publishes a new tag revision.",
      impact: "A future delivery run can execute different third-party code without a corresponding workflow review.",
      recommendation: "Pin delivery-related actions to full commit SHAs and update those pins through reviewed automation.",
      remediation: { complexity: "small" },
      tags: ["actions", "release", "supply-chain"],
    };
  }

  return {
    title: "Repository-wide GitHub Action pinning policy",
    category: "supply-chain",
    summary: `Routine CI actions use mutable tags or branches in ${observations.length} workflow location${observations.length === 1 ? "" : "s"}.\n\nAffected:\n${affected.map((item) => `- ${item}`).join("\n")}`,
    whyItMatters: "A consistent pinning policy makes routine CI reproducible and avoids reviewing the same remediation action by action.",
    impact: "Test and setup jobs can change behavior without a repository change, but they do not have the release authority identified in higher-priority findings.",
    recommendation: "Establish a repository-wide policy that pins external actions to full commit SHAs and updates them through reviewed automation.",
    remediation: { complexity: "small" },
    tags: ["actions", "supply-chain"],
  };
}

function observationData(observation: ObservationInit): Record<string, unknown> {
  return typeof observation.evidence === "object" && observation.evidence !== null && !Array.isArray(observation.evidence)
    ? observation.evidence
    : {};
}

function stringField(value: Record<string, unknown> | undefined, field: string): string | undefined {
  const item = value?.[field];
  return typeof item === "string" ? item : undefined;
}

function stringArrayField(value: Record<string, unknown>, field: string): string[] {
  const item = value[field];
  return Array.isArray(item) ? item.filter((entry): entry is string => typeof entry === "string") : [];
}

function highestConfidence(
  observations: ReadonlyArray<ObservationInit>,
  fallback: (typeof Confidence)[keyof typeof Confidence],
): (typeof Confidence)[keyof typeof Confidence] {
  const ranks = { low: 0, medium: 1, high: 2 } as const;
  let highest: (typeof Confidence)[keyof typeof Confidence] = Confidence.Low;
  for (const observation of observations) {
    const confidence = typeof observation.confidence === "string" ? observation.confidence : fallback;
    if (ranks[confidence] > ranks[highest]) {
      highest = confidence;
    }
  }
  return highest;
}

export function observationFor(detection: Detection): ObservationInit {
  const rule = RULE_MAP.get(detection.ruleId);
  if (rule === undefined) {
    throw new Error(`Unknown Depot CI rule ${detection.ruleId}.`);
  }
  return {
    ruleId: detection.ruleId,
    subject: detection.subject,
    groupKey: detection.groupKey,
    title: rule.title,
    category: rule.category,
    severity: detection.severity,
    confidence: detection.confidence,
    confidenceAggregation: "maximum",
    severityAggregation: "highest",
    location: {
      file: detection.file,
      line: detection.line,
      label: detection.label,
      snippet: detection.snippet,
    },
    evidence: {
      label: detection.label,
      ...detection.data,
    },
    tags: rule.tags,
  };
}

export function defaultSeverity(ruleId: RuleId): (typeof Severity)[keyof typeof Severity] {
  const rule = RULE_MAP.get(ruleId);
  if (rule === undefined) {
    throw new Error(`Unknown Depot CI rule ${ruleId}.`);
  }
  return rule.severity;
}

function formatSubjects(subjects: string[]): string {
  if (subjects.length === 0) {
    return "External action";
  }
  if (subjects.length === 1) {
    return subjects[0] ?? "External action";
  }
  if (subjects.length === 2) {
    return `${subjects[0]} and ${subjects[1]}`;
  }
  return `${subjects.slice(0, -1).join(", ")}, and ${subjects.at(-1)}`;
}
