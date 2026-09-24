"use client";

import { useCallback, useEffect, useState } from "react";
import { useVerify } from "@/lib/verify-context";
import { normalizeBaseUrl } from "@/lib/verify-flow";
import { Card } from "./section";
import { Disclosure } from "./disclosure";
import { CopyButton } from "./copy-button";

interface Container {
  image: string;
  digest: string;
  command?: { policy: string; argv?: string[] };
}
interface Workload {
  label: string;
  containers?: Container[];
  initContainers?: Container[];
}
interface AllowlistDoc {
  schema: string;
  workloads: Record<string, Workload>;
}

type State =
  | { status: "idle" | "loading" }
  | { status: "ok"; raw: string; doc: AllowlistDoc; sha256: string; fetchedAt: string }
  | { status: "error"; message: string };

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function ghcrUrl(image: string): string | null {
  const repo = image.split("@")[0];
  if (!repo.startsWith("ghcr.io/")) return null;
  const [, org, ...rest] = repo.split("/");
  return `https://github.com/${org}/packages/container/package/${rest.join("%2F")}`;
}

/**
 * The cluster's admission allowlist, as the router publishes it. Fail-closed
 * admission means only these exact images may run — but this copy arrives as
 * served content, so it is a statement by the endpoint, not an anchor. Pinning
 * the canonical bytes out of band and enforcing them against the mesh leaf's
 * matched-workload stamp is what turns it into one.
 */
export function AllowlistCard() {
  const { endpoint } = useVerify();
  const [state, setState] = useState<State>({ status: "idle" });

  const load = useCallback(async () => {
    const baseUrl = normalizeBaseUrl(endpoint);
    if (!baseUrl) return;
    setState({ status: "loading" });
    try {
      const res = await fetch(`${baseUrl}/allowlist`, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const raw = await res.text();
      setState({
        status: "ok",
        raw,
        doc: JSON.parse(raw) as AllowlistDoc,
        sha256: await sha256Hex(raw),
        fetchedAt: new Date().toISOString(),
      });
    } catch (e) {
      setState({ status: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, [endpoint]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">
        What may run at all: the admission allowlist
      </h2>
      <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
        Pod admission in c8s is fail-closed and does not rely on the control plane, which sits
        outside the trust boundary. Only the digests below may launch in this cluster — including
        the scan API you are talking to. This copy is served by the endpoint, so read it as a
        statement the cluster makes about itself: it becomes an anchor only when the canonical
        bytes are pinned out of band and enforced against the mesh leaf&apos;s matched-workload
        stamp.
      </p>

      {state.status === "loading" && (
        <p className="text-[0.85rem] text-muted">
          <span className="spinner mr-2 inline-block size-3 align-[-2px]" />
          Fetching the served allowlist…
        </p>
      )}
      {state.status === "error" && (
        <p className="font-mono text-[0.78rem] text-[#f85149]">
          could not fetch the allowlist: {state.message}{" "}
          <button type="button" className="underline" onClick={() => void load()}>
            retry
          </button>
        </p>
      )}

      {state.status === "ok" && (
        <>
          <ul className="flex flex-col gap-2.5">
            {Object.entries(state.doc.workloads ?? {}).map(([name, w]) => {
              const containers = [...(w.initContainers ?? []), ...(w.containers ?? [])];
              const image = containers[0]?.image ?? w.label;
              const url = ghcrUrl(image);
              return (
                <li key={name} className="border-t border-border pt-2.5 first:border-0 first:pt-0">
                  <div className="font-mono text-[0.8rem] font-semibold text-heading">{name}</div>
                  {url ? (
                    <a
                      className="block break-all font-mono text-[0.72rem] text-accent hover:underline"
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {image}
                    </a>
                  ) : (
                    <span className="block break-all font-mono text-[0.72rem] text-foreground">
                      {image}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>

          <div className="mt-4 border-t border-border pt-3">
            <div className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">
              document sha-256
            </div>
            <div className="mt-0.5 flex items-start gap-2">
              <span className="min-w-0 break-all font-mono text-[0.75rem]">{state.sha256}</span>
              <span className="code-block shrink-0 opacity-100">
                <CopyButton text={state.sha256} />
              </span>
            </div>
            <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">
              Compare this against the canonical document your operator publishes. If they differ,
              the cluster is not enforcing what you were told it enforces.
            </p>
          </div>

          <div className="mt-3">
            <Disclosure summary="View the served allowlist" meta="JSON">
              <div className="mb-1 flex justify-end">
                <CopyButton text={state.raw} />
              </div>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
                <code>{JSON.stringify(state.doc, null, 2)}</code>
              </pre>
            </Disclosure>
          </div>
        </>
      )}
    </Card>
  );
}
