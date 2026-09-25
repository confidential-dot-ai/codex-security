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
        This page checks that for you, here, in this tab. Your browser asks the machine for a
        signed report that only genuine Intel TDX hardware can produce, and compares it against
        the exact software this cluster is supposed to be running. If anything fails to match, the
        page says so and nothing is sent.
      </p>

      <p className="mt-4 text-[1.02rem] leading-relaxed text-foreground">
        If every check passes, the same run opens an encrypted channel that only the verified
        enclave can read, and the <a href="/scan">scan console</a> speaks through it.
      </p>
    </div>
  );
}
