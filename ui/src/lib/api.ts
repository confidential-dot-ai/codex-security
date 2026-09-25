"use client";

// The scan API, spoken over the attested channel. Every call goes through
// Session.fetch, so the request and response are sealed to the enclave whose
// measurements the browser pinned — the bearer token included, which is the
// point: it is never exposed to whatever terminates TLS in front of the
// cluster.

import { C8sVerifyError } from "c8s-verify";
import type { RequestInit as TunnelInit, Session } from "c8s-verify";

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface ScanJob {
  id: string;
  repository: string;
  revision: string;
  status: ScanStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  error?: string;
  result?: { status: string; coverage?: string; warning?: string };
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * The endpoint rejected the tunnel request itself, before the scan API saw it:
 * the session id is no longer one it holds. That is a channel failure, not an
 * authorization failure, however much the status code looks like one.
 */
function isChannelLost(e: unknown): boolean {
  return e instanceof C8sVerifyError && e.code === "channel_error";
}

export class ScanApi {
  /**
   * Takes a session *getter* rather than a session, because a quiet reconnect
   * replaces the session object underneath: holding the old one would keep
   * sealing requests to a channel the endpoint has already forgotten.
   */
  constructor(
    private readonly getSession: () => Session | null,
    private readonly token: string,
    private readonly renew?: () => Promise<boolean>,
  ) {}

  async #send(path: string, init?: TunnelInit): Promise<{ status: number; text: string }> {
    const session = this.getSession();
    if (!session) {
      throw new ApiError(0, "No attested channel is open. Verify the endpoint first.");
    }
    const response = await session.fetch(path, {
      ...init,
      headers: { Authorization: `Bearer ${this.token}`, ...(init?.headers ?? {}) },
    });
    return { status: response.status, text: response.text() };
  }

  async #call(path: string, init?: TunnelInit): Promise<{ status: number; text: string }> {
    try {
      return await this.#send(path, init);
    } catch (e) {
      // A session outlives neither a cluster restart nor the endpoint's own
      // expiry. Re-verify once — which re-runs every check, so the retry is
      // sent to an enclave that has just proven itself again — and retry.
      if (isChannelLost(e) && this.renew && (await this.renew())) {
        return await this.#send(path, init);
      }
      if (isChannelLost(e)) {
        throw new ApiError(
          0,
          "The attested channel is no longer open — the session expired, or the cluster restarted. Verify again to open a new one.",
        );
      }
      throw e;
    }
  }

  async #json<T>(path: string, init?: TunnelInit): Promise<T> {
    const { status, text } = await this.#call(path, init);
    if (status === 401) {
      throw new ApiError(status, "The API token was rejected.");
    }
    if (status >= 400) {
      let message = `HTTP ${status}`;
      try {
        const parsed = JSON.parse(text) as { message?: string; error?: string };
        message = parsed.message ?? parsed.error ?? message;
      } catch {
        if (text.trim()) message = text.trim().slice(0, 300);
      }
      throw new ApiError(status, message);
    }
    return JSON.parse(text) as T;
  }

  /** Queue a scan. Omitting the revision lets the service resolve HEAD. */
  async submit(repository: string, revision?: string): Promise<ScanJob> {
    return await this.#json<ScanJob>("/v1/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(revision ? { repository, revision } : { repository }),
    });
  }

  async list(): Promise<ScanJob[]> {
    const { scans } = await this.#json<{ scans: ScanJob[] }>("/v1/scans");
    return scans;
  }

  async get(id: string): Promise<ScanJob> {
    return await this.#json<ScanJob>(`/v1/scans/${encodeURIComponent(id)}`);
  }

  async log(id: string): Promise<string> {
    const { text } = await this.#call(`/v1/scans/${encodeURIComponent(id)}/log`);
    return text;
  }

  async files(id: string): Promise<string[]> {
    const { files } = await this.#json<{ files: string[] }>(
      `/v1/scans/${encodeURIComponent(id)}/files`,
    );
    return files;
  }

  async file(id: string, path: string): Promise<string> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const { text } = await this.#call(`/v1/scans/${encodeURIComponent(id)}/files/${encoded}`);
    return text;
  }
}

/** A job is still moving; the console keeps polling while this is true. */
export function isPending(job: ScanJob): boolean {
  return job.status === "queued" || job.status === "running";
}

/**
 * bulk-scan exits nonzero for any repository that is not fully complete, so a
 * partial-coverage scan still produced a report. The service reports the
 * per-repository status separately; surface that rather than the exit code.
 */
export function outcomeOf(job: ScanJob): { label: string; tone: "good" | "warn" | "bad" } {
  if (job.status === "completed") {
    if (job.result?.coverage && job.result.coverage !== "complete") {
      return { label: `completed — coverage ${job.result.coverage}`, tone: "warn" };
    }
    return { label: "completed", tone: "good" };
  }
  if (job.status === "failed") return { label: job.result?.status ?? "failed", tone: "bad" };
  return { label: job.status, tone: "warn" };
}
