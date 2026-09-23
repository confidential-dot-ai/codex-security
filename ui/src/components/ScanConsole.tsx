"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, isPending, outcomeOf, ScanApi, type ScanJob } from "@/lib/api";

const TONE_COLOR = { good: "var(--good)", warn: "var(--warn)", bad: "var(--bad)" } as const;

function Outcome({ job }: { job: ScanJob }) {
  const { label, tone } = outcomeOf(job);
  return (
    <span className="mono text-xs" style={{ color: TONE_COLOR[tone] }}>
      {label}
    </span>
  );
}

function shortRepo(url: string): string {
  return url.replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\.git$/, "");
}

export function ScanConsole({ api }: { api: ScanApi }) {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [repository, setRepository] = useState("https://github.com/octocat/Hello-World");
  const [revision, setRevision] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const next = await api.list();
      if (mounted.current) setJobs(next);
    } catch (e) {
      if (mounted.current) setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Poll only while something is actually moving, so an idle console is quiet.
  useEffect(() => {
    if (!jobs.some(isPending)) return;
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [jobs, refresh]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const job = await api.submit(repository.trim(), revision.trim() || undefined);
      setJobs((prev) => [job, ...prev]);
      setSelected(job.id);
      setRevision("");
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 400
          ? `${e.message} (the service requires an https URL, and a full 40-character commit SHA if you supply one)`
          : e instanceof Error
            ? e.message
            : String(e),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <form onSubmit={submit} className="panel p-4 space-y-3">
        <div className="text-sm font-medium">Submit a scan</div>
        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <input
            className="field mono"
            value={repository}
            onChange={(e) => setRepository(e.target.value)}
            placeholder="https://github.com/owner/repo"
            spellCheck={false}
            required
          />
          <button className="btn" type="submit" disabled={busy || !repository.trim()}>
            {busy ? "Submitting…" : "Scan"}
          </button>
        </div>
        <input
          className="field mono"
          value={revision}
          onChange={(e) => setRevision(e.target.value)}
          placeholder="revision (optional) — full 40-character commit SHA; blank resolves HEAD"
          spellCheck={false}
        />
        <p className="text-xs" style={{ color: "var(--muted)" }}>
          The repository is cloned and scanned inside the enclave you verified above. The request,
          your token included, is sealed to it.
        </p>
        {error && (
          <p className="mono text-xs" style={{ color: "var(--bad)" }}>
            {error}
          </p>
        )}
      </form>

      <div className="panel">
        <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: "var(--line)" }}>
          <span className="text-sm font-medium">Scans</span>
          <button className="btn-ghost" onClick={() => void refresh()} type="button">
            Refresh
          </button>
        </div>
        {jobs.length === 0 ? (
          <p className="px-4 py-6 text-sm" style={{ color: "var(--muted)" }}>
            No scans yet.
          </p>
        ) : (
          <ul>
            {jobs.map((job) => (
              <li key={job.id} className="border-b last:border-0" style={{ borderColor: "var(--line)" }}>
                <button
                  type="button"
                  className="w-full text-left px-4 py-3 flex items-baseline justify-between gap-4"
                  onClick={() => setSelected(selected === job.id ? null : job.id)}
                >
                  <span className="min-w-0">
                    <span className="mono text-sm">{shortRepo(job.repository)}</span>
                    <span className="mono text-xs block truncate" style={{ color: "var(--muted)" }}>
                      {job.revision.slice(0, 12)} · {new Date(job.createdAt).toLocaleTimeString()}
                    </span>
                  </span>
                  <Outcome job={job} />
                </button>
                {selected === job.id && <JobDetail api={api} job={job} />}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function JobDetail({ api, job }: { api: ScanApi; job: ScanJob }) {
  const [tab, setTab] = useState<"log" | "report">("log");
  const [log, setLog] = useState<string>("");
  const [report, setReport] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const text = await api.log(job.id);
        if (live) setLog(text);
      } catch (e) {
        if (live) setNote(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      live = false;
    };
  }, [api, job.id, job.status]);

  useEffect(() => {
    if (tab !== "report" || report !== null || isPending(job)) return;
    let live = true;
    void (async () => {
      try {
        const files = await api.files(job.id);
        const path = files.find((f) => f.endsWith("report.md"));
        if (!path) {
          if (live) setReport("No report.md was produced for this scan.");
          return;
        }
        const text = await api.file(job.id, path);
        if (live) setReport(text);
      } catch (e) {
        if (live) setReport(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      live = false;
    };
  }, [api, job, report, tab]);

  return (
    <div className="px-4 pb-4 space-y-3">
      <div className="flex gap-2">
        {(["log", "report"] as const).map((id) => (
          <button
            key={id}
            type="button"
            className="btn-ghost"
            style={tab === id ? { borderColor: "var(--accent)", color: "var(--accent)" } : undefined}
            onClick={() => setTab(id)}
          >
            {id === "log" ? "Log" : "Report"}
          </button>
        ))}
        {job.result?.warning && (
          <span className="mono text-xs self-center" style={{ color: "var(--warn)" }}>
            {job.result.warning}
          </span>
        )}
      </div>
      <pre
        className="mono text-xs whitespace-pre-wrap overflow-auto max-h-96 p-3 rounded"
        style={{ background: "#0d1015", border: "1px solid var(--line)", color: "var(--ink)" }}
      >
        {tab === "log"
          ? log || note || "Waiting for output…"
          : isPending(job)
            ? "The scan is still running."
            : (report ?? "Loading report…")}
      </pre>
    </div>
  );
}
