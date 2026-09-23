import { SITE } from "@/lib/config";

const REFERENCES = [
  {
    k: "The platform",
    t: "c8s · Confidential Kubernetes",
    v: "Fail-closed pod admission, RA-TLS service mesh, measured node images.",
    href: SITE.c8s,
    go: "Source",
  },
  {
    k: "The verifier on this page",
    t: "c8s-verify-js",
    v: "DCAP verification compiled to WebAssembly, plus the PQ channel. Vendored with its WASM, MIT.",
    href: SITE.verifyLib,
    go: "Source",
  },
  {
    k: "The workload",
    t: "codex-security",
    v: "The scan API is sdk/typescript/src/server/scans.ts; the console is ui/.",
    href: SITE.repo,
    go: "Source",
  },
  {
    k: "The endpoint",
    t: SITE.defaultEndpoint,
    v: "The c8s router in front of the scan API. Its serving certificate is CDS-issued and attestation-bound, not WebPKI.",
    href: SITE.defaultEndpoint,
    go: "Open once to accept the certificate",
  },
];

export function References() {
  return (
    <section className="mt-12 border-t border-border pt-8" id="references">
      <h2 className="mb-2 text-2xl font-semibold tracking-[0.01em] text-heading">
        Built on open, inspectable pieces
      </h2>
      <p className="mb-5 max-w-[68ch] text-[0.95rem] leading-relaxed text-foreground">
        Every link in the chain is public: the platform source, the image the measurements came
        from, the scanner, and the verifier running on this page.
      </p>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {REFERENCES.map((r) => (
          <div key={r.t} className="flex flex-col gap-1.5 rounded-lg border border-border bg-card p-4">
            <span className="font-mono text-[0.65rem] uppercase tracking-[0.1em] text-muted">
              {r.k}
            </span>
            <span className="font-semibold text-heading">{r.t}</span>
            <span className="whitespace-pre-line break-all font-mono text-[0.78rem] leading-relaxed text-muted">
              {r.v}
            </span>
            <span className="mt-auto pt-1 font-mono text-[0.85rem]">
              <a href={r.href} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                {r.go} ↗
              </a>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
