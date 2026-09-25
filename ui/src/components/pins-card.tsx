"use client";

import { useVerify } from "@/lib/verify-context";
import type { PinsState } from "@/lib/verify-context";
import { Card } from "./section";
import { Disclosure } from "./disclosure";
import { CopyButton } from "./copy-button";

const REGS: { k: keyof PinsState; label: string; covers: string }[] = [
  {
    k: "mrtd",
    label: "MRTD",
    covers: "The TDVF firmware regions only. On TDX this does not identify the guest OS.",
  },
  {
    k: "rtmr1",
    label: "RTMR[1]",
    covers: "The guest kernel: the UKI PE image, the GPT layout and the boot path.",
  },
  {
    k: "rtmr2",
    label: "RTMR[2]",
    covers:
      "The kernel command line, which carries the dm-verity root hash — and so the whole guest rootfs.",
  },
];

export function PinsCard() {
  const { pins } = useVerify();

  return (
    <Card>
      <Disclosure summary="Pinned measurements" meta="what this page requires">
        <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
          Verification requires the quote to report exactly these values. They ship with this page
          from the image build and from an operator, never from the endpoint under test — which is
          the whole point of a pin. Any difference fails closed.
        </p>

        <div className="flex flex-col gap-4">
          {REGS.map((r) => (
            <div key={r.k}>
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="font-mono text-[0.8rem] font-semibold text-heading">
                  {r.label}
                </span>
                <CopyButton text={pins[r.k]} />
              </div>
              <code className="block break-all rounded-md border border-border bg-[var(--pre-bg)] px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground">
                {pins[r.k]}
              </code>
              <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">{r.covers}</p>
            </div>
          ))}

          <div>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-mono text-[0.8rem] font-semibold text-heading">Mesh CA</span>
              <CopyButton text={pins.meshCaPem} />
            </div>
            <code className="block whitespace-pre-wrap break-all rounded-md border border-border bg-[var(--pre-bg)] px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground">
              {pins.meshCaPem.split("\n").slice(0, 2).join("\n")}
              {"\n… " + (pins.meshCaPem.split("\n").length - 2) + " more lines"}
            </code>
            <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">
              Cluster identity. The attested serving leaf must chain to it, which is what makes the
              verdict specific-cluster rather than some genuine TDX machine.
            </p>
          </div>
        </div>
      </Disclosure>
    </Card>
  );
}
