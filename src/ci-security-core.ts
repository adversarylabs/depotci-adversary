/**
 * Shared GitHub Actions / Depot CI security detectors.
 * Keep this file in sync with depotci-adversary/src/ci-security-core.ts
 * (same logic; each repo maps keys to its own rule ids).
 */

export interface CiSecurityHit {
  key:
    | "unpinned-action"
    | "write-all"
    | "pull-request-target-pwn"
    | "script-injection"
    | "self-hosted-untrusted"
    | "contents-write-on-pr"
    | "runs-on-expression"
    | "secret-scope-job"
  file: string
  line: number
  snippet: string
  label: string
  data: Record<string, unknown>
}

export function detectCiSecurityIssues(file: string, source: string): CiSecurityHit[] {
  const hits: CiSecurityHit[] = []
  const lines = source.split(/\r?\n/)

  const hasPullRequest = /\bpull_request(?:_target)?\b/i.test(source)
  const hasPullRequestTarget = /\bpull_request_target\b/i.test(source)

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ""
    const lineNo = i + 1
    const snippet = line.trim().slice(0, 240)

    // Unpinned third-party actions (not full SHA)
    const uses = line.match(/uses:\s*([\w.-]+\/[\w./-]+)@([^\s#]+)/i)
    if (uses) {
      const ref = uses[2] ?? ""
      if (!/^[0-9a-fA-F]{40}$/.test(ref)) {
        hits.push({
          key: "unpinned-action",
          file,
          line: lineNo,
          snippet,
          label: `Action ${uses[1]} uses mutable ref @${ref}`,
          data: { action: uses[1], ref },
        })
      }
    }

    if (/permissions:\s*write-all/i.test(line)) {
      hits.push({
        key: "write-all",
        file,
        line: lineNo,
        snippet,
        label: "Workflow grants write-all token permissions",
        data: {},
      })
    }

    if (
      hasPullRequestTarget &&
      /github\.event\.pull_request\.head\.(?:sha|ref)/i.test(line)
    ) {
      hits.push({
        key: "pull-request-target-pwn",
        file,
        line: lineNo,
        snippet,
        label: "pull_request_target checks out untrusted PR head",
        data: { trigger: "pull_request_target" },
      })
    }

    // Script injection: untrusted event fields inside run: lines
    if (
      /^\s*(?:-\s*)?run:/.test(line) ||
      (i > 0 && isContinuedRunBlock(lines, i))
    ) {
      const inj =
        /\$\{\{\s*github\.event\.(?:issue|comment|discussion|pull_request|review|review_comment|head_commit)\.[^}]+\}\}/i.exec(
          line,
        )
      if (inj) {
        hits.push({
          key: "script-injection",
          file,
          line: lineNo,
          snippet,
          label: "Untrusted github.event field interpolated into run step",
          data: { expression: inj[0] },
        })
      }
    }

    if (hasPullRequest && /runs-on:\s*(?:\[\s*)?self-hosted\b/i.test(line)) {
      hits.push({
        key: "self-hosted-untrusted",
        file,
        line: lineNo,
        snippet,
        label: "Self-hosted runner used with pull_request",
        data: {},
      })
    }

    if (hasPullRequest && /contents:\s*write/i.test(line)) {
      hits.push({
        key: "contents-write-on-pr",
        file,
        line: lineNo,
        snippet,
        label: "contents: write granted on pull_request workflow",
        data: {},
      })
    }

    if (/runs-on:\s*\$\{\{[^}]+\}\}/i.test(line)) {
      hits.push({
        key: "runs-on-expression",
        file,
        line: lineNo,
        snippet,
        label: "runs-on uses an expression (possible runner label injection)",
        data: {},
      })
    }
  }

  // Job-level secrets when job has multiple steps (depot secret.scope-broad)
  const jobSecretHits = detectJobLevelSecrets(file, lines)
  hits.push(...jobSecretHits)

  return hits
}

function isContinuedRunBlock(lines: string[], index: number): boolean {
  // Walk backward to find if we're inside a run: | block
  for (let j = index; j >= 0; j--) {
    const line = lines[j] ?? ""
    if (/^\s*(?:-\s*)?run:\s*[|>]/.test(line)) return true
    if (/^\s*-\s+\w/.test(line) && j !== index) return false
    if (/^\S/.test(line) && !/^\s*#/.test(line) && j !== index) return false
  }
  return false
}

function detectJobLevelSecrets(file: string, lines: string[]): CiSecurityHit[] {
  const hits: CiSecurityHit[] = []
  let inJob = false
  let jobLine = 0
  let jobSnippet = ""
  let jobHasSecretsEnv = false
  let stepCount = 0
  let envSecrets = false

  const flush = () => {
    if (inJob && jobHasSecretsEnv && stepCount > 1) {
      hits.push({
        key: "secret-scope-job",
        file,
        line: jobLine,
        snippet: jobSnippet,
        label: "Job-level secrets exposed to multiple steps",
        data: { stepCount },
      })
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? ""
    if (/^\s{2}[A-Za-z0-9_-]+:\s*$/.test(line) && !/^\s{2}(steps|needs|runs-on|permissions|env|if|strategy|defaults|timeout|concurrency|environment|container|services|outputs|continue-on-error|name):/.test(line)) {
      // possible job id at 2-space indent under jobs:
      // simplistic: track steps under jobs
    }
    if (/^\s{2}[A-Za-z0-9_-]+:/.test(line) && i > 0) {
      // new top-level under jobs - approximate job boundary when we see runs-on
    }
    if (/runs-on:/.test(line)) {
      flush()
      inJob = true
      jobLine = i + 1
      jobSnippet = line.trim().slice(0, 240)
      jobHasSecretsEnv = envSecrets
      stepCount = 0
      envSecrets = false
    }
    if (inJob && /secrets\.[A-Za-z0-9_]+/.test(line) && /^\s+env:/.test(line) === false) {
      // env block secret assignment nearby
      if (/\$\{\{\s*secrets\./i.test(line) && !/^\s+-\s/.test(line)) {
        // job-level env entries are typically indented under env: without list dash for the key
        const prev = lines[i - 1] ?? ""
        if (/env:/.test(prev) || /^\s{4,6}[A-Z0-9_]+:/.test(line)) {
          jobHasSecretsEnv = true
        }
      }
    }
    if (inJob && /^\s+-\s+(name:|uses:|run:)/.test(line)) {
      stepCount += 1
    }
    if (/^jobs:/.test(line)) {
      flush()
      inJob = false
    }
  }
  flush()
  return hits
}

/** Map shared keys to github-actions catalog rule ids. */
export const GHA_RULE_IDS: Record<CiSecurityHit["key"], string | null> = {
  "unpinned-action": "gha.action.unpinned-tag",
  "write-all": "gha.permissions.write-all",
  "pull-request-target-pwn": "gha.pull-request-target.pwn",
  "script-injection": "gha.script-injection.context",
  "self-hosted-untrusted": "gha.self-hosted.untrusted",
  "contents-write-on-pr": "gha.permissions.contents-write-on-pr",
  "runs-on-expression": "gha.runs-on.expression",
  "secret-scope-job": null, // depot-only P0 mapping
}

/** Map shared keys to depotci rule ids (depotci-adversary). */
export const DEPOT_RULE_IDS: Record<CiSecurityHit["key"], string | null> = {
  "unpinned-action": "depotci.action.unpinned",
  "write-all": "depotci.permissions.broad",
  "pull-request-target-pwn": "depotci.pull-request.untrusted-code",
  "script-injection": "depotci.script-injection",
  "self-hosted-untrusted": "depotci.runs-on.self-hosted",
  "contents-write-on-pr": "depotci.permissions.broad",
  "runs-on-expression": "depotci.runs-on.self-hosted",
  "secret-scope-job": "depotci.secret.scope-broad",
}
