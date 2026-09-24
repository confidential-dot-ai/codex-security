"use client";

import { useVerify } from "@/lib/verify-context";
import { SITE } from "@/lib/config";
import { Disclosure } from "./disclosure";
import { CopyButton } from "./copy-button";

function Row({ label, pinned, measured }: { label: string; pinned: string; measured?: string }) {
  const match = measured !== undefined && measured.toLowerCase() === pinned.toLowerCase();
  return (
    <tr>
      <td className="whitespace-nowrap pr-4 font-semibold text-heading">{label}</td>
      <td
        className={`break-all font-mono text-[0.72rem] leading-relaxed ${
          match ? "text-foreground" : "text-[#f85149]"
        }`}
      >
        {measured ?? "-"}
      </td>
      <td className="pl-3 text-right align-top">
        {measured !== undefined && (
          <span
            className={`rounded-full border px-2 py-0.5 font-mono text-[0.62rem] uppercase tracking-wider ${
              match ? "border-ok/50 text-ok" : "border-[#f85149]/60 text-[#f85149]"
            }`}
          >
            {match ? "✓" : "✕"}
          </span>
        )}
      </td>
    </tr>
  );
}

export function Verdict() {
  const { status, result, error, pins } = useVerify();
  if (status === "idle" || status === "running") return null;

  if (status === "fail" || !result) {
    return (
      <div
        className="rounded-lg border border-[#f85149] bg-[#f85149]/10 p-4 sm:p-5"
        role="alert"
        id="verdict"
        data-state="fail"
      >
        <h3 className="mb-1 text-lg font-semibold text-heading">Verification failed closed.</h3>
        <p className="text-[0.9rem] text-foreground">
          One check did not pass. No channel was opened and no scan was sent. A genuine enclave
          running different software fails in exactly this way.
        </p>
        <p className="mt-2 break-all font-mono text-[0.78rem] leading-relaxed text-muted">
          {error?.code ? `[${error.code}] ` : ""}
          {error?.message ?? "unknown error"}
        </p>
        {SITE.frontDoor === "cds" && (
          <p className="mt-2 text-[0.85rem] leading-relaxed text-muted">
            If the browser could not reach the endpoint at all, open it in a tab once and accept its
            certificate. This deployment&apos;s serving certificate is CDS-issued and
            attestation-bound, not WebPKI, so a browser will not trust it on sight — and the fetch
            then fails before any attestation happens.
          </p>
        )}
      </div>
    );
  }

  const a = result.attestation;
  const m = result.measured;

  const rawReport = (() => {
    const seen = new WeakSet();
    return JSON.stringify(
      a,
      (k, val) => {
        if (typeof val === "bigint") return String(val);
        if (val instanceof Uint8Array)
          return "0x" + [...val].map((b) => b.toString(16).padStart(2, "0")).join("");
        if (typeof val === "object" && val !== null) {
          if (seen.has(val)) return "[circular]";
          seen.add(val);
        }
        return val;
      },
      2,
    );
  })();

  return (
    <div className="rounded-lg border border-ok bg-ok/10 p-4 sm:p-5" id="verdict" data-state="ok">
      <h3 className="mb-1 text-lg font-semibold text-heading">
        This is a verified confidential scan endpoint.
      </h3>
      <p className="mb-3 text-[0.9rem] text-foreground">
        Every check ran in this browser tab just now. No server of ours was involved.
      </p>
      <ul className="mb-4 flex flex-col gap-1.5">
        {[
          "Real Intel TDX silicon. The hardware attestation chains to Intel's root of trust (DCAP), verified in this browser.",
          "Exactly the published software. Firmware, guest kernel and kernel command line all match the pinned image (MRTD, RTMR[1], RTMR[2]) — and RTMR[2] carries the dm-verity root hash, so the whole rootfs is pinned with it.",
          "This cluster, not merely a genuine one. The serving certificate chains to the mesh CA pinned out of band.",
          "A sealed channel to that enclave. Scans, findings and your API token are encrypted to it, not to the proxy in front of it.",
        ].map((t) => (
          <li key={t.slice(0, 24)} className="flex gap-2 text-[0.92rem] leading-relaxed">
            <span className="font-bold text-ok">✓</span>
            <span>{t}</span>
          </li>
        ))}
      </ul>

      <div className="overflow-x-auto border-t border-border pt-3">
        <table className="w-full border-collapse">
          <tbody>
            <Row label="MRTD" pinned={pins.mrtd} measured={m.mrtd} />
            <Row label="RTMR[1]" pinned={pins.rtmr1} measured={m.rtmr1} />
            <Row label="RTMR[2]" pinned={pins.rtmr2} measured={m.rtmr2} />
          </tbody>
        </table>
      </div>

      <dl className="mt-3 grid grid-cols-1 gap-x-8 gap-y-2 border-t border-border pt-3 text-[0.85rem] sm:grid-cols-2">
        <div>
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">platform</dt>
          <dd>{a.platform}, bare-metal Intel TDX (DCAP)</dd>
        </div>
        <div>
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">verdict</dt>
          <dd>{a.trustClass}</dd>
        </div>
        <div>
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            front door
          </dt>
          <dd>
            {a.frontDoorMode}
            {a.frontDoorMode === "cds" || a.frontDoorMode === "acme"
              ? " — the serving key is held inside the enclave, which is why the transport binding to this exact leaf was served at all"
              : " — the serving key is not enclave-held, so the transport binding was not served"}
          </dd>
        </div>
        <div>
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">freshness</dt>
          <dd>report_data binds this session and nonce: {String(a.reportDataMatch)}</dd>
        </div>
        <div>
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            cert issuer
          </dt>
          <dd>{a.cert.issuerCN ?? "-"}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">
            mesh CA sha-256 (pinned out of band)
          </dt>
          <dd className="break-all font-mono text-[0.75rem]">{a.cert.caSha256}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">session</dt>
          <dd className="break-all font-mono text-[0.75rem]">
            {result.sessionId} · verified {new Date(result.verifiedAt).toLocaleString()}
          </dd>
        </div>
        <div className="sm:col-span-2">
          <Disclosure summary="View raw report data" meta="JSON">
            <div className="mb-1 flex justify-end">
              <CopyButton text={rawReport} />
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-[var(--pre-bg)] p-3 font-mono text-[0.72rem] leading-relaxed">
              <code>{rawReport}</code>
            </pre>
          </Disclosure>
        </div>
      </dl>
    </div>
  );
}
