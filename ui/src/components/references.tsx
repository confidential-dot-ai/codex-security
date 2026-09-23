import { DEPLOYMENT, SITE } from "@/lib/config";

const REFERENCES = [
  {
    k: "The workload, by digest",
    t: "codex-security scan API",
    v: `${DEPLOYMENT.image}@${DEPLOYMENT.digest}`,
    href: DEPLOYMENT.imageUrl,
    note: "The exact image admitted for the endpoint you just verified. Pull it and read what runs.",
  },
  {
    k: "The platform",
    t: "c8s · Confidential Kubernetes",
    v: DEPLOYMENT.release,
    href: DEPLOYMENT.releaseUrl,
    note: "Fail-closed pod admission, an RA-TLS service mesh, and measured node images. Public TLS here is terminated by the router's in-guest ACME sidecar, so the serving key stays enclave-held.",
  },
  {
    k: "The verifier on this page",
    t: "c8s-verify-js",
    v: "vendored at d589419",
    href: SITE.verifyLib,
    note: "DCAP verification compiled to WebAssembly, plus the post-quantum channel. Vendored with its WASM because it is not published to npm.",
  },
  {
    k: "The protocol",
    t: "attest-pq · PROTOCOL.md",
    v: "client-first X-Wing exchange",
    href: "https://github.com/confidential-dot-ai/c8s-verify-js/blob/main/PROTOCOL.md",
    note: "Written down normatively: the identity transcript, the report_data binding, and the sealed record format.",
  },
  {
    k: "The source",
    t: "codex-security",
    v: "sdk/typescript/src/server/scans.ts · ui/",
    href: SITE.repo,
    note: "The scan API and this console. The fork adds both; the scanner itself is upstream.",
  },
];

export function References() {
  return (
    <section className="mt-12 border-t border-border pt-8" id="references">
      <h2 className="mb-2 text-2xl font-semibold tracking-[0.01em] text-heading">
        Built on open, inspectable pieces
      </h2>
      <p className="mb-5 max-w-[68ch] text-[0.95rem] leading-relaxed text-foreground">
        Every link in the chain is public: the exact image behind the endpoint, the platform it
        runs on, the verifier running on this page, and the protocol they speak.
      </p>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {REFERENCES.map((r) => (
          <div key={r.t} className="flex flex-col gap-1.5 rounded-lg border border-border bg-card p-4">
            <span className="font-mono text-[0.65rem] uppercase tracking-[0.1em] text-muted">
              {r.k}
            </span>
            <span className="font-semibold text-heading">{r.t}</span>
            <a
              className="break-all font-mono text-[0.78rem] leading-relaxed text-accent hover:underline"
              href={r.href}
              target="_blank"
              rel="noreferrer"
            >
              {r.v} ↗
            </a>
            <span className="mt-auto pt-1 text-[0.78rem] leading-relaxed text-muted">{r.note}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
