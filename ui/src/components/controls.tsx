"use client";

import Link from "next/link";
import { useVerify } from "@/lib/verify-context";
import { SITE } from "@/lib/config";
import { Card } from "./section";

export function Controls() {
  const { endpoint, setEndpoint, status, run, disconnect, result } = useVerify();
  const running = status === "running";

  return (
    <Card>
      <div className="grid grid-cols-1 gap-3">
        <label className="block">
          <span className="mb-1 block font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            Scan API endpoint
          </span>
          <input
            id="endpoint"
            type="text"
            inputMode="url"
            spellCheck={false}
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            disabled={running || status === "ok"}
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-[0.85rem] text-foreground outline-none focus:border-accent disabled:opacity-60"
          />
        </label>
        <div className="block">
          <span className="mb-1 block font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            Platform
          </span>
          <div className="w-full rounded-md border border-border bg-[var(--pre-bg)] px-3 py-2 font-mono text-[0.85rem] text-muted">
            {SITE.platformLabel}
          </div>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-4">
        {status === "ok" ? (
          <>
            <Link href="/scan" className="cta">
              Open the scan console →
            </Link>
            <button type="button" onClick={disconnect} className="cta cta-ghost">
              Disconnect
            </button>
          </>
        ) : (
          <button id="verify" type="button" onClick={run} disabled={running} className="cta">
            {running ? (
              <>
                <span className="spinner size-3.5 border-[var(--cta-text)]/40 border-t-[var(--cta-text)]" />
                Verifying…
              </>
            ) : (
              "Verify the cluster"
            )}
          </button>
        )}
        <span className="text-[0.82rem] text-muted">
          {status === "ok"
            ? `Verified ${result ? new Date(result.verifiedAt).toLocaleTimeString() : ""}. A sealed channel is open.`
            : status === "fail"
              ? "Failed closed. Nothing was trusted, and no channel was opened."
              : running
                ? "Fetching a fresh hardware report…"
                : ""}
        </span>
      </div>
      {status !== "ok" && SITE.frontDoor === "cds" && (
        <p className="mt-3 text-[0.8rem] leading-relaxed text-muted">
          First time against this endpoint?{" "}
          <a href={endpoint} target="_blank" rel="noreferrer">
            Open it in a tab
          </a>{" "}
          and accept its certificate once. It is CDS-issued and attestation-bound, not WebPKI, so
          until then the browser blocks the request before any attestation can run.
        </p>
      )}
      {endpoint.trim().replace(/\/+$/, "") !== SITE.defaultEndpoint && (
        <p className="mt-2 text-[0.8rem] text-warn">
          Non-default endpoint. The pins on this page still decide pass or fail.
        </p>
      )}
    </Card>
  );
}
