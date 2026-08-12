export type StringMap = Record<string, unknown>;

export interface SourceLocation {
  line: number;
  snippet: string;
}

export interface WorkflowStep {
  index: number;
  name: string;
  id?: string;
  uses?: string;
  run?: string;
  if?: string;
  continueOnError: boolean;
  env: StringMap;
  with: StringMap;
  raw: StringMap;
  location: SourceLocation;
  fieldLocations: Partial<Record<"uses", SourceLocation>>;
}

export interface WorkflowJob {
  id: string;
  name: string;
  runsOn?: string;
  timeoutMinutes?: number | string;
  needs: string[];
  if?: string;
  permissions?: unknown;
  env: StringMap;
  outputs: StringMap;
  steps: WorkflowStep[];
  uses?: string;
  raw: StringMap;
  location: SourceLocation;
  fieldLocations: Partial<Record<"uses", SourceLocation>>;
}

export interface DepotWorkflow {
  path: string;
  name: string;
  events: Set<string>;
  permissions?: unknown;
  env: StringMap;
  concurrency?: unknown;
  jobs: WorkflowJob[];
  raw: StringMap;
  source: string;
  location: SourceLocation;
  fieldLocations: Partial<Record<"on" | "permissions" | "env" | "concurrency", SourceLocation>>;
}

export interface ParseFailure {
  path: string;
  message: string;
  line: number;
  column?: number;
  snippet: string;
}

export type WorkflowParseResult =
  | { kind: "workflow"; workflow: DepotWorkflow }
  | { kind: "unsupported" }
  | { kind: "failure"; failure: ParseFailure };

export interface RepositoryContext {
  files: Set<string>;
  lockfiles: string[];
  dockerfiles: Array<{ path: string; source: string }>;
}

export function isRecord(value: unknown): value is StringMap {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function expressionText(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value === undefined || value === null) {
    return "";
  }
  return JSON.stringify(value);
}
