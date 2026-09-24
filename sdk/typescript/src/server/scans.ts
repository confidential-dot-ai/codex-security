import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import { join, normalize, resolve, sep } from "node:path";

export type ScanJobStatus = "queued" | "running" | "completed" | "failed";

export interface ScanJob {
  id: string;
  repository: string;
  revision: string;
  status: ScanJobStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  error?: string;
  /** Per-repository outcome from bulk-scan's results.jsonl. */
  result?: {
    status: string;
    coverage?: string;
    warning?: string;
  };
}

export interface ScanSubmission {
  repository: string;
  revision?: string;
}

const GIT_URL = /^https:\/\/[^\s]+$/;
const FULL_SHA = /^[0-9a-f]{40}$/;
const LOG_TAIL_BYTES = 64 * 1024;

export function validateScanSubmission(
  input: unknown,
): input is ScanSubmission {
  if (typeof input !== "object" || input === null) return false;
  const candidate = input as Record<string, unknown>;
  if (
    typeof candidate["repository"] !== "string" ||
    !GIT_URL.test(candidate["repository"])
  )
    return false;
  if (
    candidate["revision"] !== undefined &&
    (typeof candidate["revision"] !== "string" ||
      !FULL_SHA.test(candidate["revision"]))
  )
    return false;
  return true;
}

/**
 * Runs submitted scans one at a time by driving the bulk-scan CLI command as a
 * child process, so a scan started over HTTP takes exactly the code path the
 * containerized bulk scanner already exercises. Job state is in memory; the
 * scan artifacts live under the scans directory and survive a restart.
 */
export class ScanRunner {
  readonly #jobs = new Map<string, ScanJob>();
  readonly #queue: string[] = [];
  readonly #scansDir: string;
  readonly #extraArguments: readonly string[];
  readonly #environment: NodeJS.ProcessEnv;
  #active: ChildProcess | null = null;

  public constructor(environment: NodeJS.ProcessEnv = process.env) {
    this.#environment = environment;
    // Not under CODEX_SECURITY_STATE_DIR: bulk-scan refuses an output
    // directory inside its protected scan root.
    this.#scansDir = resolve(
      environment["CODEX_SECURITY_SCANS_DIR"] ??
        join(environment["CODEX_HOME"] ?? "/state", "scans"),
    );
    const extra = environment["CODEX_SECURITY_SCAN_ARGS"] ?? "";
    this.#extraArguments = extra.split(/\s+/).filter((value) => value !== "");
  }

  public list(): ScanJob[] {
    return [...this.#jobs.values()].sort((a, b) =>
      b.createdAt.localeCompare(a.createdAt),
    );
  }

  public get(id: string): ScanJob | undefined {
    return this.#jobs.get(id);
  }

  public async submit(submission: ScanSubmission): Promise<ScanJob> {
    const revision =
      submission.revision ?? (await resolveHead(submission.repository));
    const job: ScanJob = {
      id: randomUUID(),
      repository: submission.repository,
      revision,
      status: "queued",
      createdAt: new Date().toISOString(),
    };
    this.#jobs.set(job.id, job);
    this.#queue.push(job.id);
    void this.#drain();
    return job;
  }

  public async streamLog(id: string, response: ServerResponse): Promise<void> {
    const logPath = join(this.#jobDir(id), "scan.log");
    const info = await stat(logPath);
    const start = Math.max(0, info.size - LOG_TAIL_BYTES);
    response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    createReadStream(logPath, { start }).pipe(response);
  }

  public async listFiles(id: string): Promise<string[]> {
    const outputDir = join(this.#jobDir(id), "output");
    const entries = await readdir(outputDir, {
      recursive: true,
      withFileTypes: true,
    });
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) =>
        join(entry.parentPath, entry.name).slice(outputDir.length + 1),
      )
      .sort();
  }

  public async streamFile(
    id: string,
    relativePath: string,
    response: ServerResponse,
  ): Promise<boolean> {
    const outputDir = join(this.#jobDir(id), "output");
    const target = normalize(join(outputDir, relativePath));
    if (target !== outputDir && !target.startsWith(outputDir + sep))
      return false;
    const info = await stat(target);
    if (!info.isFile()) return false;
    response.writeHead(200, {
      "Content-Type": target.endsWith(".json")
        ? "application/json"
        : "text/plain; charset=utf-8",
    });
    createReadStream(target).pipe(response);
    return true;
  }

  #jobDir(id: string): string {
    if (!this.#jobs.has(id)) throw new Error(`unknown scan job: ${id}`);
    return join(this.#scansDir, id);
  }

  async #drain(): Promise<void> {
    if (this.#active !== null) return;
    const id = this.#queue.shift();
    if (id === undefined) return;
    const job = this.#jobs.get(id)!;
    try {
      await this.#run(job);
    } finally {
      this.#active = null;
      void this.#drain();
    }
  }

  async #run(job: ScanJob): Promise<void> {
    const jobDir = join(this.#scansDir, job.id);
    const outputDir = join(jobDir, "output");
    await mkdir(outputDir, { recursive: true });
    const csvPath = join(jobDir, "repositories.csv");
    await writeFile(
      csvPath,
      `id,repository,revision\n${job.id},${job.repository},${job.revision}\n`,
    );
    job.status = "running";
    job.startedAt = new Date().toISOString();
    const logPath = join(jobDir, "scan.log");
    await writeFile(logPath, "");
    const child = spawn(
      process.execPath,
      [
        process.argv[1]!,
        "bulk-scan",
        csvPath,
        "--output-dir",
        outputDir,
        ...this.#extraArguments,
      ],
      { env: { ...this.#environment }, stdio: ["ignore", "pipe", "pipe"] },
    );
    this.#active = child;
    const log = createWriteStream(logPath, { flags: "a" });
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
    const exitCode: number = await new Promise((resolveExit) => {
      child.once("error", (error) => {
        job.error = error.message;
        resolveExit(-1);
      });
      child.once("exit", (code) => resolveExit(code ?? -1));
    });
    log.end();
    job.exitCode = exitCode;
    job.finishedAt = new Date().toISOString();
    // bulk-scan exits nonzero for any not-fully-completed repository, so the
    // per-repository status in results.jsonl is the authoritative outcome: a
    // scan with partial coverage still produced findings and a report.
    job.result = await readResult(outputDir, job.id);
    job.status =
      exitCode === 0 || job.result?.status.startsWith("completed") === true
        ? "completed"
        : "failed";
  }
}

async function readResult(
  outputDir: string,
  id: string,
): Promise<ScanJob["result"]> {
  try {
    const lines = (await readFile(join(outputDir, "results.jsonl"), "utf8"))
      .split("\n")
      .filter((line) => line !== "");
    for (const line of lines) {
      const row = JSON.parse(line) as Record<string, unknown>;
      if (row["id"] !== id || typeof row["status"] !== "string") continue;
      return {
        status: row["status"],
        ...(typeof row["coverage"] === "string"
          ? { coverage: row["coverage"] }
          : {}),
        ...(typeof row["warning"] === "string"
          ? { warning: row["warning"] }
          : {}),
      };
    }
  } catch {
    // No results file: the scan failed before writing one.
  }
  return undefined;
}

async function resolveHead(repository: string): Promise<string> {
  const child = spawn("git", ["ls-remote", repository, "HEAD"], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
  const exitCode: number = await new Promise((resolveExit) => {
    child.once("error", () => resolveExit(-1));
    child.once("exit", (code) => resolveExit(code ?? -1));
  });
  const sha = Buffer.concat(chunks).toString("utf8").split(/\s/)[0] ?? "";
  if (exitCode !== 0 || !FULL_SHA.test(sha))
    throw new ScanRequestError(
      `could not resolve HEAD of ${repository}; supply a full 40-character revision`,
    );
  return sha;
}

export class ScanRequestError extends Error {}
