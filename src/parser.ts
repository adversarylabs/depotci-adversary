import {
  LineCounter,
  isMap,
  isNode,
  isScalar,
  isSeq,
  parseDocument,
  type Pair,
  type YAMLMap,
} from "yaml";
import {
  type DepotWorkflow,
  type ParseFailure,
  type SourceLocation,
  type StringMap,
  type WorkflowJob,
  type WorkflowParseResult,
  type WorkflowStep,
  isRecord,
  stringValue,
} from "./model.js";

export function parseDepotWorkflow(path: string, source: string): WorkflowParseResult {
  const lineCounter = new LineCounter();
  const document = parseDocument(source, {
    lineCounter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });

  if (document.errors.length > 0) {
    const error = document.errors[0];
    const position = error.linePos?.[0] ?? lineCounter.linePos(error.pos[0]);
    return {
      kind: "failure",
      failure: failure(path, source, position.line, `YAML ${error.code.toLowerCase().replaceAll("_", " ")}: ${cleanErrorMessage(error.message)}`, position.col),
    };
  }

  if (!isMap(document.contents)) {
    return { kind: "unsupported" };
  }

  const root = document.contents;
  const jobsPair = findPair(root, "jobs");
  if (jobsPair === undefined) {
    return { kind: "unsupported" };
  }
  if (!isMap(jobsPair.value)) {
    return structureFailure(path, source, jobsPair.value ?? jobsPair.key, lineCounter, "The jobs field must be a mapping of job IDs to job definitions.");
  }

  let raw: StringMap;
  try {
    raw = toRecord(document.toJS({ maxAliasCount: 50 }));
  } catch (error) {
    return {
      kind: "failure",
      failure: failure(
        path,
        source,
        1,
        `The workflow could not be normalized safely: ${error instanceof Error ? error.message : "unknown YAML conversion error"}`,
      ),
    };
  }
  const jobs: WorkflowJob[] = [];
  let supportedJobCount = 0;

  for (const pair of jobsPair.value.items) {
    const id = scalarString(pair.key);
    if (id === undefined || id.length === 0) {
      return structureFailure(path, source, pair.key, lineCounter, "Every job must have a string job ID.");
    }
    if (!isMap(pair.value)) {
      return structureFailure(path, source, pair.value ?? pair.key, lineCounter, `Job ${id} must be a mapping.`);
    }

    const parsed = parseJob(path, source, id, pair.value, lineCounter);
    if (parsed.kind === "failure") {
      return parsed;
    }
    jobs.push(parsed.job);
    if (parsed.job.runsOn !== undefined || parsed.job.uses !== undefined || parsed.job.steps.length > 0) {
      supportedJobCount += 1;
    }
  }

  if (jobs.length === 0 || supportedJobCount === 0) {
    return { kind: "unsupported" };
  }

  const name = stringValue(raw.name) ?? filenameWithoutExtension(path);
  const workflow: DepotWorkflow = {
    path,
    name,
    events: parseEvents(raw.on),
    permissions: raw.permissions,
    env: toRecord(raw.env),
    concurrency: raw.concurrency,
    jobs: jobs.sort((left, right) => left.id.localeCompare(right.id)),
    raw,
    source,
    location: locationFor(root, source, lineCounter),
    fieldLocations: Object.fromEntries(
      (["on", "permissions", "env", "concurrency"] as const).flatMap((field) => {
        const pair = findPair(root, field);
        return pair === undefined ? [] : [[field, locationFor(pair.key, source, lineCounter)]];
      }),
    ),
  };

  return { kind: "workflow", workflow };
}

type ParsedJob = { kind: "job"; job: WorkflowJob } | { kind: "failure"; failure: ParseFailure };

function parseJob(path: string, source: string, id: string, node: YAMLMap<unknown, unknown>, lineCounter: LineCounter): ParsedJob {
  const raw = toRecord(node.toJSON());
  const stepsPair = findPair(node, "steps");
  const steps: WorkflowStep[] = [];

  if (stepsPair !== undefined) {
    if (!isSeq(stepsPair.value)) {
      return structureFailure(path, source, stepsPair.value ?? stepsPair.key, lineCounter, `Job ${id} has a steps field that is not a sequence.`);
    }
    for (const [index, item] of stepsPair.value.items.entries()) {
      if (!isMap(item)) {
        return structureFailure(path, source, item, lineCounter, `Step ${index + 1} in job ${id} must be a mapping.`);
      }
      const stepRaw = toRecord(item.toJSON());
      steps.push({
        index,
        name: stringValue(stepRaw.name) ?? stringValue(stepRaw.uses) ?? `step ${index + 1}`,
        id: stringValue(stepRaw.id),
        uses: stringValue(stepRaw.uses),
        run: stringValue(stepRaw.run),
        if: stringValue(stepRaw.if),
        continueOnError: stepRaw["continue-on-error"] === true,
        env: toRecord(stepRaw.env),
        with: toRecord(stepRaw.with),
        raw: stepRaw,
        location: locationFor(item, source, lineCounter),
        fieldLocations: locationsForFields(item, ["uses"], source, lineCounter),
      });
    }
  }

  const needsResult = parseNeeds(raw.needs);
  if (needsResult === undefined) {
    const needsPair = findPair(node, "needs");
    return structureFailure(path, source, needsPair?.value ?? needsPair?.key ?? node, lineCounter, `Job ${id} has a needs field that is neither a job ID nor a sequence of job IDs.`);
  }

  return {
    kind: "job",
    job: {
      id,
      name: stringValue(raw.name) ?? id,
      runsOn: stringValue(raw["runs-on"]),
      timeoutMinutes: typeof raw["timeout-minutes"] === "number" || typeof raw["timeout-minutes"] === "string"
        ? raw["timeout-minutes"]
        : undefined,
      needs: needsResult,
      if: stringValue(raw.if),
      permissions: raw.permissions,
      env: toRecord(raw.env),
      outputs: toRecord(raw.outputs),
      steps,
      uses: stringValue(raw.uses),
      raw,
      location: locationFor(node, source, lineCounter),
      fieldLocations: locationsForFields(node, ["uses"], source, lineCounter),
    },
  };
}

function parseNeeds(value: unknown): string[] | undefined {
  if (value === undefined || value === null) {
    return [];
  }
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return [...new Set(value)].sort();
  }
  return undefined;
}

function parseEvents(value: unknown): Set<string> {
  if (typeof value === "string") {
    return new Set([value]);
  }
  if (Array.isArray(value)) {
    return new Set(value.filter((event): event is string => typeof event === "string"));
  }
  if (isRecord(value)) {
    return new Set(Object.keys(value));
  }
  return new Set();
}

function findPair(map: YAMLMap<unknown, unknown>, key: string): Pair<unknown, unknown> | undefined {
  return map.items.find((pair) => scalarString(pair.key) === key);
}

function scalarString(node: unknown): string | undefined {
  return isScalar(node) && typeof node.value === "string" ? node.value : undefined;
}

function locationFor(node: unknown, source: string, lineCounter: LineCounter): SourceLocation {
  const line = !isNode(node) || node.range === undefined || node.range === null ? 1 : lineCounter.linePos(node.range[0]).line;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim() ?? "" };
}

function locationsForFields<Field extends string>(
  map: YAMLMap<unknown, unknown>,
  fields: readonly Field[],
  source: string,
  lineCounter: LineCounter,
): Partial<Record<Field, SourceLocation>> {
  return Object.fromEntries(fields.flatMap((field) => {
    const pair = findPair(map, field);
    return pair === undefined ? [] : [[field, locationFor(pair.key, source, lineCounter)]];
  })) as Partial<Record<Field, SourceLocation>>;
}

function structureFailure(
  path: string,
  source: string,
  node: unknown,
  lineCounter: LineCounter,
  message: string,
): { kind: "failure"; failure: ParseFailure } {
  const location = locationFor(node, source, lineCounter);
  return { kind: "failure", failure: failure(path, source, location.line, message) };
}

function failure(path: string, source: string, line: number, message: string, column?: number): ParseFailure {
  return {
    path,
    message,
    line,
    column,
    snippet: source.split(/\r?\n/)[line - 1]?.trim() ?? "",
  };
}

function cleanErrorMessage(message: string): string {
  return message.replace(/ at line \d+, column \d+.*$/s, "").trim();
}

function toRecord(value: unknown): StringMap {
  return isRecord(value) ? value : {};
}

function filenameWithoutExtension(path: string): string {
  const filename = path.split("/").pop() ?? path;
  return filename.replace(/\.ya?ml$/i, "");
}
