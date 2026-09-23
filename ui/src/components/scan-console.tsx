"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, isPending, outcomeOf, ScanApi, type ScanJob } from "@/lib/api";
import { useVerify } from "@/lib/verify-context";
import { Card } from "./section";
import { Markdown } from "./markdown";
import { CopyButton } from "./copy-button";

function shortRepo(url: string): string {
  return url.replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\.git$/, "");
}

function duration(job: ScanJob): string | null {
  if (!job.startedAt) return null;
  const end = job.finishedAt ? new Date(job.finishedAt).getTime() : Date.now();
  const secs = Math.max(0, Math.round((end - new Date(job.startedAt).getTime()) / 1000));
  return secs < 90 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

function Outcome({ job }: { job: ScanJob }) {
  const { label, tone } = outcomeOf(job);
  const cls =
    tone === "good"
      ? "border-ok/50 text-ok"
      : tone === "bad"
        ? "border-[#f85149]/60 text-[#f85149]"
        : "border-warn/60 text-warn";
  return (
    <span
      className={`shrink-0 whitespace-nowrap rounded-full border px-2 py-0.5 font-mono text-[0.62rem] uppercase tracking-wider ${cls}`}
    >
      {isPending(job) && <span className="spinner mr-1 inline-block size-2.5 align-[-1px]" />}
      {label}
    </span>
  );
}

export function ScanConsole() {
  const { getSession, token, setToken, verifyEpoch, reconnect } = useVerify();

  const api = useMemo(() => {
    const session = getSession();
    return session && token ? new ScanApi(session, token) : null;
    // A new channel means a new session object; rebuild the client with it.
  }, [getSession, token, verifyEpoch]);

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

  // Jobs belong to the channel they were listed over.
  useEffect(() => {
    setJobs([]);
    setSelected(null);
  }, [verifyEpoch]);

  const refresh = useCallback(async () => {
    if (!api) return;
    try {
      const next = await api.list();
      if (mounted.current) {
        setJobs(next);
        setError(null);
      }
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
    if (!api) return;
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
    <div className="flex flex-col gap-6">
      <Card>
        <label className="block">
          <span className="mb-1 block font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            API token
          </span>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="bearer token for /v1/scans"
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-[0.85rem] text-foreground outline-none focus:border-accent"
          />
        </label>
        <p className="mt-1 text-[0.8rem] leading-relaxed text-muted">
          Held in this tab only — never stored, and sent sealed inside the attested channel, so the
          proxy terminating TLS in front of the cluster never sees it.
        </p>
      </Card>

      <form onSubmit={submit}>
        <Card>
          <h2 className="mb-3 text-lg font-semibold text-heading">Submit a scan</h2>
          <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
            <input
              value={repository}
              onChange={(e) => setRepository(e.target.value)}
              placeholder="https://github.com/owner/repo"
              spellCheck={false}
              required
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-[0.85rem] text-foreground outline-none focus:border-accent"
            />
            <button className="cta" type="submit" disabled={busy || !api || !repository.trim()}>
              {busy ? (
                <>
                  <span className="spinner size-3.5 border-[var(--cta-text)]/40 border-t-[var(--cta-text)]" />
                  Submitting…
                </>
              ) : (
                "Scan"
              )}
            </button>
          </div>
          <input
            value={revision}
            onChange={(e) => setRevision(e.target.value)}
            placeholder="revision (optional) — full 40-character commit SHA; blank resolves HEAD"
            spellCheck={false}
            className="mt-3 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-[0.85rem] text-foreground outline-none focus:border-accent"
          />
          <p className="mt-2 text-[0.8rem] leading-relaxed text-muted">
            The repository is cloned and scanned inside the enclave you verified. The request, and
            the findings that come back, are sealed to it.
          </p>
          {!token && (
            <p className="mt-2 font-mono text-[0.78rem] text-warn">
              Enter the API token above to submit scans.
            </p>
          )}
          {error && (
            <p className="mt-2 break-all font-mono text-[0.78rem] text-[#f85149]">
              {error}{" "}
              <button
                type="button"
                className="underline"
                onClick={() => void reconnect().then(() => refresh())}
              >
                re-verify and retry
              </button>
            </p>
          )}
        </Card>
      </form>

      <div className="rounded-lg border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-4 py-3 sm:px-5">
          <h2 className="text-lg font-semibold text-heading">Scans</h2>
          <button type="button" className="cta cta-ghost" onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
        {jobs.length === 0 ? (
          <p className="px-4 py-6 text-[0.9rem] text-muted sm:px-5">
            {api ? "No scans yet." : "Connect and enter a token to list scans."}
          </p>
        ) : (
          <ul>
            {jobs.map((job) => (
              <li key={job.id} className="border-b border-border last:border-0">
                <button
                  type="button"
                  className="flex w-full items-baseline justify-between gap-4 px-4 py-3 text-left hover:bg-[var(--row-hover)] sm:px-5"
                  onClick={() => setSelected(selected === job.id ? null : job.id)}
                  aria-expanded={selected === job.id}
                >
                  <span className="min-w-0">
                    <span className="font-mono text-[0.88rem] text-heading">
                      {shortRepo(job.repository)}
                    </span>
                    <span className="block truncate font-mono text-[0.72rem] text-muted">
                      {job.revision.slice(0, 12)} · {new Date(job.createdAt).toLocaleTimeString()}
                      {duration(job) ? ` · ${duration(job)}` : ""}
                      {job.exitCode !== undefined ? ` · exit ${job.exitCode}` : ""}
                    </span>
                  </span>
                  <Outcome job={job} />
                </button>
                {selected === job.id && api && <JobDetail api={api} job={job} />}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

type Tab = "log" | "report" | "files";

function JobDetail({ api, job }: { api: ScanApi; job: ScanJob }) {
  const [tab, setTab] = useState<Tab>(isPending(job) ? "log" : "report");
  const [log, setLog] = useState("");
  const [report, setReport] = useState<string | null>(null);
  const [files, setFiles] = useState<string[] | null>(null);
  const [openFile, setOpenFile] = useState<{ path: string; text: string } | null>(null);
  const [note, setNote] = useState<string | null>(null);

  // Tail the log while the job is moving, not only when its status changes.
  useEffect(() => {
    let live = true;
    const pull = async () => {
      try {
        const text = await api.log(job.id);
        if (live) setLog(text);
      } catch (e) {
        if (live) setNote(e instanceof Error ? e.message : String(e));
      }
    };
    void pull();
    if (!isPending(job)) return () => {
      live = false;
    };
    const timer = setInterval(() => void pull(), 5000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [api, job]);

  useEffect(() => {
    if (isPending(job)) return;
    let live = true;
    void (async () => {
      try {
        const list = await api.files(job.id);
        if (!live) return;
        setFiles(list);
        const path = list.find((f) => f.endsWith("report.md"));
        if (!path) {
          setReport("No report.md was produced for this scan.");
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
  }, [api, job]);

  const TABS: { id: Tab; label: string }[] = [
    { id: "log", label: "Log" },
    { id: "report", label: "Report" },
    { id: "files", label: files ? `Artifacts (${files.length})` : "Artifacts" },
  ];

  return (
    <div className="border-t border-border bg-[var(--card-muted)] px-4 py-4 sm:px-5">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded-md border px-2.5 py-1 font-mono text-[0.72rem] uppercase tracking-wider transition-colors ${
              tab === t.id
                ? "border-accent text-accent"
                : "border-border text-muted hover:text-foreground"
            }`}
          >
            {t.label}
          </button>
        ))}
        {job.result?.warning && (
          <span className="font-mono text-[0.72rem] text-warn">{job.result.warning}</span>
        )}
        {job.error && <span className="font-mono text-[0.72rem] text-[#f85149]">{job.error}</span>}
      </div>

      {tab === "log" && (
        <div className="code-block">
          <CopyButton text={log} />
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
            <code>{log || note || "Waiting for output…"}</code>
          </pre>
        </div>
      )}

      {tab === "report" &&
        (isPending(job) ? (
          <p className="text-[0.9rem] text-muted">The scan is still running.</p>
        ) : report === null ? (
          <p className="text-[0.9rem] text-muted">Loading report…</p>
        ) : (
          <div className="rounded-md border border-border bg-card p-4">
            <div className="mb-2 flex justify-end">
              <CopyButton text={report} label="copy markdown" />
            </div>
            <Markdown text={report} />
          </div>
        ))}

      {tab === "files" &&
        (files === null ? (
          <p className="text-[0.9rem] text-muted">
            {isPending(job) ? "Artifacts appear when the scan finishes." : "Loading artifacts…"}
          </p>
        ) : (
          <div>
            <ul className="flex flex-col gap-1">
              {files.map((f) => (
                <li key={f}>
                  <button
                    type="button"
                    className="break-all text-left font-mono text-[0.78rem] text-accent hover:underline"
                    onClick={async () => {
                      try {
                        setOpenFile({ path: f, text: await api.file(job.id, f) });
                      } catch (e) {
                        setOpenFile({
                          path: f,
                          text: e instanceof Error ? e.message : String(e),
                        });
                      }
                    }}
                  >
                    {f}
                  </button>
                </li>
              ))}
            </ul>
            {openFile && (
              <div className="code-block mt-3">
                <CopyButton text={openFile.text} />
                <p className="mb-1 break-all font-mono text-[0.72rem] text-muted">
                  {openFile.path}
                </p>
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
                  <code>{openFile.text}</code>
                </pre>
              </div>
            )}
          </div>
        ))}
    </div>
  );
}
