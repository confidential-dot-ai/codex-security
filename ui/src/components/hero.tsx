import { SITE } from "@/lib/config";

export function Hero() {
  return (
    <div className="mb-8">
      <h1 className="mb-4 text-3xl font-semibold leading-tight tracking-[0.01em] text-heading sm:text-4xl">
        A confidential code-scanning endpoint you can check yourself
      </h1>
      <p className="text-[1.02rem] leading-relaxed text-foreground">
        This is the{" "}
        <a href={SITE.repo} target="_blank" rel="noreferrer">
          codex-security
        </a>{" "}
        scan API, served from <code>{SITE.defaultEndpoint}</code>. It clones a repository and scans
        it with an agent, so the code it reads and the findings it writes are exactly the material
        you would not want a normal cloud service to hold. It therefore runs as a confidential
        workload on{" "}
        <a href={SITE.c8s} target="_blank" rel="noreferrer">
          c8s (Confidential Kubernetes)
        </a>{" "}
        on an Intel TDX node, inside a CVM whose whole disk image is measured.
      </p>
      <p className="mt-4 text-[1.02rem] leading-relaxed text-foreground">
        This page fetches a fresh, nonce-bound TDX quote and verifies it in your browser: the DCAP
        certificate chain, the firmware and guest measurements against pins you hold out of band,
        and the serving certificate against the cluster&apos;s own mesh CA. No server of ours takes
        part in the check. If every check passes, the same run opens a post-quantum sealed channel
        to the enclave, and the{" "}
        <a href="/scan">scan console</a> speaks only through that channel — so the repository URL,
        the findings and your API token are never visible to whatever terminates TLS in front of
        the cluster.
      </p>
    </div>
  );
}
