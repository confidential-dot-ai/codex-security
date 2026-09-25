"use client";

import { useVerify } from "@/lib/verify-context";
import { TrustStrip } from "@/components/trust-strip";
import { ScanConsole } from "@/components/scan-console";

export default function ScanPage() {
  const { status } = useVerify();
  return (
    <main className="mx-auto max-w-[860px] px-5 py-10 md:py-14">
      <div className="mb-8">
        <h1 className="mb-4 text-3xl font-semibold leading-tight tracking-[0.01em] text-heading sm:text-4xl">
          Scan a repository inside the enclave
        </h1>
        <p className="text-[1.02rem] leading-relaxed text-foreground">
          codex-security clones the repository you name and scans it with an agent, entirely inside
          the confidential VM. Everything on this page travels through the sealed channel that
          verification opened, so the repository URL, the log, the findings and your API token are
          readable only to the enclave whose measurements you pinned.
        </p>
      </div>
      <div className="flex flex-col gap-6">
        <TrustStrip />
        {status === "ok" && <ScanConsole />}
      </div>
    </main>
  );
}
