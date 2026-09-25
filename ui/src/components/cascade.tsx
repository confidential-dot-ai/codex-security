"use client";

import { useVerify } from "@/lib/verify-context";
import type { StepId, StepState } from "@/lib/verify-flow";
import { Card } from "./section";

interface StepDef {
  id: StepId;
  title: string;
  proves: string;
  tech: string;
}

const PHASES: { name: string; steps: StepDef[] }[] = [
  {
    name: "Fresh, genuine hardware evidence",
    steps: [
      {
        id: "nonce",
        title: "Fresh evidence, made for this session",
        proves:
          "The attestation was produced just now, for your browser. It is not replayed from an earlier session or another machine.",
        tech:
          "A 32-byte nonce is generated in this tab and echoed by the enclave. The TD quote's report_data must bind it, via a SHA-384 transcript over the session keys, nonce, mesh leaf and issuing CA. Stale or replayed evidence fails closed.",
      },
      {
        id: "dcap",
        title: "Real Intel TDX silicon",
        proves:
          "The hardware quote is genuine. Its signature chains to Intel's root of trust. A simulator, or a different kind of TEE, cannot pass.",
        tech:
          "The TDX quote's PCK certificate chain verifies to the pinned Intel SGX Root CA inside the attestation-rs WASM verifier. The QE report binding is checked and debug-enabled TDs are rejected. Revocation collateral is not checked in the browser.",
      },
    ],
  },
  {
    name: "The exact published image",
    steps: [
      {
        id: "mrtd",
        title: "The pinned firmware",
        proves: "The enclave booted exactly the audited firmware, not a modified lookalike.",
        tech:
          "MRTD is the SHA-384 launch measurement of the TDVF firmware regions. It must equal the reference from the node image manifest. MRTD alone does not identify the guest OS - two different cluster images can share it - so the next two registers do the real work.",
      },
      {
        id: "rtmr1",
        title: "The pinned guest kernel",
        proves: "The Linux kernel inside the enclave is exactly the one from the published image.",
        tech:
          "RTMR stands for run-time measurement register. RTMR[1] covers the guest kernel: the UKI PE image, the GPT layout and the boot path. It is compared exactly against the image manifest.",
      },
      {
        id: "rtmr2",
        title: "The pinned kernel command line and rootfs",
        proves:
          "The whole guest filesystem matches the audited image: every system binary, every config file, and the scanner itself.",
        tech:
          "RTMR[2] covers the kernel command line, which carries the dm-verity root hash of the guest rootfs. Pinning it pins the entire filesystem, because dm-verity checks every block against that hash at read time.",
      },
    ],
  },
  {
    name: "This deployment, this cluster",
    steps: [
      {
        id: "meshca",
        title: "This cluster's identity",
        proves:
          "The endpoint belongs to this cluster. Its serving certificate chains to the mesh CA you pinned out of band. The verdict is specific-cluster, not some genuine TDX machine.",
        tech:
          "The mesh leaf proves possession of its private key with an ECDSA P-384 signature over the identity transcript. It must chain to the pinned c8s Mesh CA. The transcript commits to the issuing CA, so a substituted chain fails closed.",
      },
    ],
  },
  {
    name: "The sealed channel",
    steps: [
      {
        id: "channel",
        title: "A sealed, post-quantum channel",
        proves:
          "Scan requests now travel inside encryption that only the verified enclave can open. The TLS terminator and every middlebox see only ciphertext - including your API token.",
        tech:
          "ML-KEM-768 plus X25519 hybrid key agreement, then HKDF-SHA-256 to an AES-256-GCM key. Every /v1/scans call rides POST /.well-known/c8s/tunnel. The channel keys are bound into the quote's report_data, so the thing you verified is the thing you are talking to.",
      },
    ],
  },
];

function Dot({ state }: { state: StepState }) {
  if (state === "active") {
    return <span className="spinner mt-0.5 size-4 shrink-0" aria-label="checking" />;
  }
  const cls =
    state === "pass"
      ? "border-ok bg-ok text-[var(--background)]"
      : state === "fail"
        ? "border-[#f85149] bg-[#f85149] text-white"
        : "border-border text-muted";
  return (
    <span
      className={`mt-0.5 grid size-4 shrink-0 place-items-center rounded-full border-2 text-[0.6rem] font-bold ${cls}`}
      aria-hidden
    >
      {state === "pass" ? "✓" : state === "fail" ? "✕" : state === "skip" ? "-" : ""}
    </span>
  );
}

function Chip({ state }: { state: StepState }) {
  if (state === "pass")
    return (
      <span className="shrink-0 whitespace-nowrap rounded-full border border-ok/50 px-2.5 py-1 font-mono text-[0.72rem] uppercase tracking-wider text-ok">
        <span className="text-[1.3em] leading-none">✓</span> verified
      </span>
    );
  if (state === "fail")
    return (
      <span className="shrink-0 whitespace-nowrap rounded-full border border-[#f85149]/60 px-2 py-0.5 font-mono text-[0.62rem] uppercase tracking-wider text-[#f85149]">
        ✕ failed
      </span>
    );
  if (state === "skip")
    return (
      <span className="shrink-0 whitespace-nowrap rounded-full border border-border px-2 py-0.5 font-mono text-[0.62rem] uppercase tracking-wider text-muted">
        not reached
      </span>
    );
  return null;
}

export function Cascade() {
  const { steps, error } = useVerify();
  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">What gets checked</h2>

      {PHASES.map((phase, pi) => (
        <div key={phase.name} className={pi > 0 ? "mt-5" : ""}>
          <p className="mb-2 border-t border-border pt-3 text-[0.95rem] font-semibold text-heading">
            {phase.name}
          </p>
          <ol>
            {phase.steps.map((s) => {
              const st = steps[s.id];
              return (
                <li key={s.id} className="cascade-row" data-step={s.id} data-state={st.state}>
                  <Dot state={st.state} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-3">
                      <span
                        className={`text-[0.95rem] font-semibold ${
                          st.state === "skip" ? "text-muted" : "text-heading"
                        }`}
                      >
                        {s.title}
                      </span>
                      <Chip state={st.state} />
                    </div>
                    <p className="mt-0.5 text-[0.85rem] leading-relaxed text-foreground">
                      {s.proves}
                    </p>
                    <p className="mt-1 break-words text-[0.8rem] leading-relaxed text-muted">
                      {s.tech}
                    </p>
                    {st.state === "pass" && st.detail && (
                      <p className="mt-1 break-all font-mono text-[0.72rem] leading-relaxed text-ok">
                        {st.detail}
                      </p>
                    )}
                    {st.state === "fail" && (
                      <p className="mt-1 break-all font-mono text-[0.75rem] leading-relaxed text-[#f85149]">
                        {error?.code ? `[${error.code}] ` : ""}
                        {st.detail ?? error?.message}
                      </p>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      ))}
    </Card>
  );
}
