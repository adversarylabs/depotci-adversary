import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface Detection {
  ruleId: RuleId;
  subject: string;
  groupKey: string;
  severity?: Severity;
  confidence?: Confidence;
  file: string;
  line: number;
  snippet: string;
  label: string;
  data: Record<string, unknown>;
  locality?: {
    kind: "direct";
    anchors: number[];
  };
}

export type RuleId =
  | "depotci.workflow.parse-error"
  | "depotci.action.unpinned"
  | "depotci.action.unsupported-input"
  | "depotci.job.missing-timeout"
  | "depotci.job.dependency-structure"
  | "depotci.cache.unstable-key"
  | "depotci.cache.missing"
  | "depotci.cache.lifecycle"
  | "depotci.build.cache-order"
  | "depotci.secret.scope"
  | "depotci.pull-request.untrusted-code"
  | "depotci.permissions.broad"
  | "depotci.step.failure-masked"
  | "depotci.release.missing-gate"
  | "depotci.workflow.redundant-work"
  | "depotci.workflow.concurrency"
  | "depotci.build.mutable-input"
  | "depotci.script-injection"
  | "depotci.runs-on.self-hosted"
  | "depotci.secret.scope-broad";
