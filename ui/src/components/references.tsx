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
    v: "github.com/confidential-dot-ai/c8s-verify-js",
    href: SITE.verifyLib,
    note: "DCAP verification compiled to WebAssembly, plus the post-quantum channel. Every check on this page is made by this library, in your browser.",
  },
  {
    k: "The source",
    t: "codex-security",
    v: "github.com/confidential-dot-ai/codex-security",
    href: SITE.repo,
    note: "The scanner, the scan API, and this console.",
  },
  {
    k: "The node image build",
    t: "confidential-os-builder",
    v: "github.com/confidential-dot-ai/confidential-os-builder",
    href: "https://github.com/confidential-dot-ai/confidential-os-builder",
    note: "Builds the measured guest image and publishes the manifest the MRTD and RTMR pins above are taken from. Reproducible builds are what make a measurement mean anything.",
  },
  {
    k: "The DCAP verifier",
    t: "attestation-rs",
    v: "github.com/confidential-dot-ai/attestation-rs",
    href: "https://github.com/confidential-dot-ai/attestation-rs",
    note: "The Rust implementation that checks the TDX quote and its Intel certificate chain. It is compiled to WebAssembly and is what actually runs in this tab.",
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
        runs on, the build that produced the measured guest, and the verifier running on this page.
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
