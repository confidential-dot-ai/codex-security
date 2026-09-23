"use client";

import Link from "next/link";
import { useVerify } from "@/lib/verify-context";
import { Card } from "./section";

/** Compact, always-visible statement of what the scan page is standing on. */
export function TrustStrip() {
  const { status, result, run, endpoint, error } = useVerify();

  if (status === "ok" && result) {
    const age = Math.max(0, Math.round((Date.now() - new Date(result.verifiedAt).getTime()) / 1000));
    return (
      <div className="rounded-lg border border-ok bg-ok/10 px-4 py-3">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <span className="text-[0.92rem] font-semibold text-heading">
            <span className="text-ok">✓</span> Sealed channel open to the verified enclave
          </span>
          <Link href="/" className="font-mono text-[0.72rem] text-accent hover:underline">
            see what was checked ↗
          </Link>
        </div>
        <p className="mt-1 break-all font-mono text-[0.72rem] leading-relaxed text-muted">
          {result.endpoint} · session {result.sessionId.slice(0, 16)}… · verified {age}s ago ·
          MRTD {result.measured.mrtd.slice(0, 16)}…
        </p>
      </div>
    );
  }

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">Verify the endpoint first</h2>
      <p className="mb-3 text-[0.92rem] leading-relaxed text-foreground">
        This console will not send a repository URL, a token, or anything else until the endpoint
        has proved, to this browser, that it is the Intel TDX enclave running the pinned image.
        Scans then ride inside the channel that proof established.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="cta" onClick={run} disabled={status === "running"}>
          {status === "running" ? (
            <>
              <span className="spinner size-3.5 border-[var(--cta-text)]/40 border-t-[var(--cta-text)]" />
              Verifying…
            </>
          ) : (
            "Verify and connect"
          )}
        </button>
        <Link href="/" className="cta cta-ghost">
          Read the trust page
        </Link>
        <span className="font-mono text-[0.72rem] text-muted">{endpoint}</span>
      </div>
      {status === "fail" && (
        <p className="mt-3 break-all font-mono text-[0.75rem] leading-relaxed text-[#f85149]">
          {error?.code ? `[${error.code}] ` : ""}
          {error?.message}
        </p>
      )}
    </Card>
  );
}
