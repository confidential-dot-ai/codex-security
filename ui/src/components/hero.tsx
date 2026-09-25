import { SITE } from "@/lib/config";

export function Hero() {
  return (
    <div className="mb-8">
      <h1 className="mb-4 text-3xl font-semibold leading-tight tracking-[0.01em] text-heading sm:text-4xl">
        Confidential Codex Security
      </h1>
      <p className="text-[1.02rem] leading-relaxed text-foreground">
        <a href={SITE.repo} target="_blank" rel="noreferrer">
          codex-security
        </a>{" "}
        reads your code to find vulnerabilities in it. This runs it as a service, on{" "}
        <a href={SITE.c8s} target="_blank" rel="noreferrer">
          confidential Kubernetes
        </a>
        , so that scanning someone else&apos;s code does not mean asking them to trust the people
        operating the service. Submit a repository and the clone, the scan and the findings all
        happen inside a hardware enclave on an Intel TDX machine. The operators cannot read any of
        it, and neither can we.
      </p>
      <p className="mt-4 text-[1.02rem] leading-relaxed text-foreground">
        You do not have to take that on faith, which is what this page is for. It asks the cluster
        for fresh hardware evidence and checks it here, in your browser: that the machine is real
        Intel TDX silicon, that it booted exactly the image whose measurements are published below,
        and that it is this cluster rather than some other genuine one. You can also see which
        image digests the cluster will run at all. Nothing is checked by a server of ours.
      </p>
      <p className="mt-4 text-[1.02rem] leading-relaxed text-foreground">
        If every check passes, the same run opens an encrypted channel that only the verified
        enclave can read, and the <a href="/scan">scan console</a> speaks through it. The
        repository you name, the findings that come back and your API token stay sealed to the
        enclave — not to whatever terminates TLS in front of it.
      </p>
    </div>
  );
}
