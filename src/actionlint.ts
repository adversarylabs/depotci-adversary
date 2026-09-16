import { readFile } from "node:fs/promises";
import { runInThisContext } from "node:vm";

export const ACTIONLINT_VERSION = "1.7.12";

export interface ActionlintError {
  message: string;
  line: number;
  column: number;
  kind: string;
}

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

interface ActionlintGlobals {
  Go?: new () => GoRuntime;
  __runActionlint?: (source: string, path: string, runnerLabels: readonly string[]) => void;
  __actionlintReady?: () => void;
  __actionlintResolve?: (errors: unknown) => void;
  __actionlintReject?: (message: string) => void;
}

const runtime = globalThis as typeof globalThis & ActionlintGlobals;
let initialization: Promise<void> | undefined;
let active = false;

export async function runActionlint(path: string, source: string, runnerLabels: readonly string[] = []): Promise<ActionlintError[]> {
  await initialize();
  if (active) throw new Error("actionlint WebAssembly runtime does not support concurrent checks");
  const run = runtime.__runActionlint;
  if (run === undefined) throw new Error("actionlint WebAssembly entrypoint is unavailable");

  active = true;
  try {
    return await new Promise<ActionlintError[]>((resolve, reject) => {
      runtime.__actionlintResolve = (value) => {
        try {
          resolve(parseErrors(value));
        } catch (error) {
          reject(error);
        }
      };
      runtime.__actionlintReject = (message) => reject(new Error(`actionlint failed: ${message}`));
      run(source, path, runnerLabels);
    });
  } finally {
    active = false;
    runtime.__actionlintResolve = undefined;
    runtime.__actionlintReject = undefined;
  }
}

function initialize(): Promise<void> {
  initialization ??= initializeRuntime();
  return initialization;
}

async function initializeRuntime(): Promise<void> {
  const shimUrl = new URL("../vendor/actionlint/wasm_exec.js", import.meta.url);
  const wasmUrl = new URL("../vendor/actionlint/actionlint.wasm", import.meta.url);
  runInThisContext(await readFile(shimUrl, "utf8"), { filename: shimUrl.pathname });
  const Go = runtime.Go;
  if (Go === undefined) throw new Error("vendored Go WebAssembly runtime did not initialize");

  const go = new Go();
  const module = await WebAssembly.compile(await readFile(wasmUrl));
  const instance = await WebAssembly.instantiate(module, go.importObject);
  await new Promise<void>((resolve, reject) => {
    runtime.__actionlintReady = resolve;
    void go.run(instance).then(
      () => reject(new Error("actionlint WebAssembly runtime exited unexpectedly")),
      reject,
    );
  });
  runtime.__actionlintReady = undefined;
}

function parseErrors(value: unknown): ActionlintError[] {
  if (!Array.isArray(value)) throw new Error("actionlint returned a non-array result");
  return value.map((item) => {
    if (typeof item !== "object" || item === null) throw new Error("actionlint returned an invalid diagnostic");
    const candidate = item as Record<string, unknown>;
    if (
      typeof candidate.message !== "string" ||
      typeof candidate.line !== "number" ||
      typeof candidate.column !== "number" ||
      typeof candidate.kind !== "string"
    ) {
      throw new Error("actionlint returned an incomplete diagnostic");
    }
    return {
      message: candidate.message,
      line: candidate.line,
      column: candidate.column,
      kind: candidate.kind,
    };
  });
}
