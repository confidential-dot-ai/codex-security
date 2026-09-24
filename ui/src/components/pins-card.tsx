"use client";

import { useVerify } from "@/lib/verify-context";
import type { PinsState } from "@/lib/verify-context";
import { Card } from "./section";
import { Disclosure } from "./disclosure";
import { looksLikePem } from "@/lib/config";

const REGS: { k: keyof PinsState; label: string; covers: string; reference: string }[] = [
  {
    k: "mrtd",
    label: "MRTD",
    covers: "Covers: TDVF firmware regions only. Does not identify the guest OS.",
    reference: "Reference: the node image's published manifest.json (tdx.mrtd).",
  },
  {
    k: "rtmr1",
    label: "RTMR[1]",
    covers: "Covers: the guest kernel. UKI PE image, GPT, boot path.",
    reference: "Reference: the node image's published manifest.json (tdx.rtmr1).",
  },
  {
    k: "rtmr2",
    label: "RTMR[2]",
    covers:
      "Covers: the kernel command line, which carries the dm-verity root hash — and so the whole guest rootfs.",
    reference: "Reference: the node image's published manifest.json (tdx.rtmr2).",
  },
];

export function PinsCard() {
  const {
    pins,
    setPin,
    pinsEditable,
    setPinsEditable,
    pinsEdited,
    resetPins,
    loadManifest,
    manifestNote,
    status,
  } = useVerify();
  const running = status === "running";

  return (
    <Card>
      <Disclosure summary="Pinned measurements" meta="read-only unless unlocked">
        <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
          Verification requires the quote to report exactly these values. They ship with this page
          from the image build and from an operator, never from the endpoint under test — that is
          the whole point. Edit a digit and the next run fails closed.
        </p>
        {pinsEdited && (
          <p className="mb-4 rounded-md border border-warn/60 bg-[var(--code-bg)] px-3 py-2 text-[0.82rem] text-warn">
            These pins no longer match the ones published with this page. A pass now only proves
            the endpoint matches what you typed.{" "}
            <button type="button" onClick={resetPins} className="underline">
              Reset to the published pins
            </button>
            .
          </p>
        )}

        <div className="mb-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            className="cta cta-ghost"
            onClick={() => setPinsEditable(!pinsEditable)}
            disabled={running}
          >
            {pinsEditable ? "Lock pins" : "Unlock to edit"}
          </button>
          <span className="text-[0.8rem] text-muted">
            A rebuilt cluster changes its RTMRs. Paste its manifest.json rather than transcribing
            hashes.
          </span>
        </div>

        <div className="flex flex-col gap-4">
          {REGS.map((r) => (
            <div key={r.k}>
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="font-mono text-[0.8rem] font-semibold text-heading">{r.label}</span>
              </div>
              {pinsEditable ? (
                <textarea
                  rows={3}
                  spellCheck={false}
                  autoCapitalize="off"
                  autoComplete="off"
                  value={pins[r.k]}
                  onChange={(e) => setPin(r.k, e.target.value.trim())}
                  disabled={running}
                  className="w-full resize-y rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground outline-none focus:border-accent disabled:opacity-60"
                />
              ) : (
                <code className="block break-all rounded-md border border-border bg-[var(--pre-bg)] px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground">
                  {pins[r.k]}
                </code>
              )}
              <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">
                {r.covers}
                <br />
                {r.reference}
              </p>
            </div>
          ))}

          {pinsEditable && (
            <div>
              <div className="mb-1 font-mono text-[0.8rem] font-semibold text-heading">
                Paste a node image manifest.json
              </div>
              <textarea
                rows={3}
                spellCheck={false}
                placeholder={'{"tdx":{"mrtd":"…","rtmr1":"…","rtmr2":"…"}}'}
                onChange={(e) => loadManifest(e.target.value)}
                disabled={running}
                className="w-full resize-y rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground outline-none focus:border-accent disabled:opacity-60"
              />
              <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">
                The same file <code>c8s verify --image-manifest</code> reads. It fills the three
                registers above verbatim.
              </p>
              {manifestNote && (
                <p className="mt-1 font-mono text-[0.75rem] text-accent">{manifestNote}</p>
              )}
            </div>
          )}

          <div>
            <div className="mb-1 font-mono text-[0.8rem] font-semibold text-heading">Mesh CA</div>
            {pinsEditable ? (
              <textarea
                rows={6}
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                value={pins.meshCaPem}
                onChange={(e) => setPin("meshCaPem", e.target.value)}
                disabled={running}
                className="w-full resize-y rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground outline-none focus:border-accent disabled:opacity-60"
              />
            ) : (
              <code className="block whitespace-pre-wrap break-all rounded-md border border-border bg-[var(--pre-bg)] px-2.5 py-2 font-mono text-[0.68rem] leading-relaxed text-foreground">
                {pins.meshCaPem.split("\n").slice(0, 2).join("\n")}
                {"\n… " + (pins.meshCaPem.split("\n").length - 2) + " more lines"}
              </code>
            )}
            <p className="mt-1 text-[0.76rem] leading-relaxed text-muted">
              Covers: cluster identity. The attested serving leaf must chain to it, which is what
              makes the verdict specific-cluster rather than some genuine TDX machine.
              <br />
              Reference: an operator, out of band.
            </p>
            {!looksLikePem(pins.meshCaPem) && (
              <p className="mt-1 font-mono text-[0.75rem] text-[#f85149]">
                That does not look like a PEM certificate.
              </p>
            )}
          </div>
        </div>
      </Disclosure>
    </Card>
  );
}
