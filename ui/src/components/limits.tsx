const LIMITS = [
  {
    t: "Which workload answered you.",
    p: "The measurements pin the node image, and the mesh CA pins the cluster. Neither proves which admitted pod served a particular request. The supportable claim is narrower: the endpoint is inside this measured cluster, and the channel is sealed to it.",
  },
  {
    t: "Revocation and platform patch level.",
    p: "DCAP collateral (PCK CRLs, TCB status, TD-QE identity) needs an asynchronous provider. The in-browser verifier skips it, so a revoked or TCB-outdated platform would still pass this page. `c8s verify` on the command line does check collateral. The quote signature chain to the Intel root is always verified here.",
  },
  {
    t: "What the scanner does with your code.",
    p: "The enclave is measured, so the scanner binary and its configuration are pinned. That is not the same as a proof about the scan's behaviour: it clones the repository you name and runs an agent over it. Read the image if you need that assurance.",
  },
  {
    t: "Mesh CA provenance.",
    p: "The pinned mesh CA is only as good as the out-of-band channel it arrived through. This page never fetches it from the endpoint under test, and it must be re-pinned after a cluster reinstall.",
  },
  {
    t: "This page's own delivery.",
    p: "Whoever hosts this page chooses the verifier and the pins. The cluster cannot make a failed check pass, but you should still compare the pins against what your operator channel publishes.",
  },
  {
    t: "The report you are shown.",
    p: "Findings are produced inside the enclave and travel back sealed, so they are not modifiable in transit. Nothing here signs the report itself, so a copy taken out of this tab carries no proof of origin.",
  },
];

export function Limits() {
  return (
    <section className="mt-12 border-t border-border pt-8" id="limits">
      <p className="mb-1 font-mono text-[0.68rem] uppercase tracking-[0.15em] text-accent">
        proves / does not prove
      </p>
      <h2 className="mb-2 text-2xl font-semibold tracking-[0.01em] text-heading">
        What this page does not prove
      </h2>
      <p className="mb-5 max-w-[68ch] text-[0.95rem] leading-relaxed text-foreground">
        Trust means stating limits plainly. Everything above is enforced in your browser on every
        run. The items below are explicitly not proven by it.
      </p>
      <ul className="flex max-w-[76ch] flex-col gap-4">
        {LIMITS.map((l) => (
          <li key={l.t} className="flex gap-3">
            <span className="font-bold text-warn" aria-hidden>
              ✕
            </span>
            <div>
              <span className="font-semibold text-heading">{l.t}</span>
              <p className="mt-0.5 text-[0.92rem] leading-relaxed text-foreground">{l.p}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
