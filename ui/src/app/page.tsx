"use client";

import { useCallback, useMemo, useState } from "react";
import { Cascade } from "@/components/Cascade";
import { ScanConsole } from "@/components/ScanConsole";
import { attest, AttestError, type AttestResult, type StepId, type StepState } from "@/lib/attest";
import { ScanApi } from "@/lib/api";
import { DEFAULT_PROFILE, looksLikePem, parseManifest, type TdxImagePin } from "@/lib/config";

const BLANK: Record<StepId, StepState> = {
  connect: "idle",
  dcap: "idle",
  mrtd: "idle",
  rtmr1: "idle",
  rtmr2: "idle",
  meshca: "idle",
  channel: "idle",
};

export default function Page() {
  const [endpoint, setEndpoint] = useState(DEFAULT_PROFILE.endpoint);
  const [token, setToken] = useState("");
  const [image, setImage] = useState<TdxImagePin>(DEFAULT_PROFILE.tdxImage);
  const [meshCa, setMeshCa] = useState(DEFAULT_PROFILE.meshCaPem);
  const [pinsOpen, setPinsOpen] = useState(false);
  const [pinNote, setPinNote] = useState<string | null>(null);

  const [states, setStates] = useState<Record<StepId, StepState>>({ ...BLANK });
  const [failure, setFailure] = useState<{ step: StepId; message: string } | null>(null);
  const [result, setResult] = useState<AttestResult | null>(null);
  const [connecting, setConnecting] = useState(false);

  const api = useMemo(
    () => (result ? new ScanApi(result.session, token) : null),
    [result, token],
  );

  const connect = useCallback(async () => {
    setConnecting(true);
    setFailure(null);
    setResult(null);
    setStates({ ...BLANK });
    try {
      const attested = await attest({
        endpoint,
        tdxImage: image,
        meshCaPem: meshCa,
        onStep: (id, state) => setStates((prev) => ({ ...prev, [id]: state })),
      });
      setResult(attested);
    } catch (error) {
      if (error instanceof AttestError) {
        setFailure({ step: error.step, message: error.message });
      } else {
        setFailure({
          step: "connect",
          message: error instanceof Error ? error.message : String(error),
        });
      }
    } finally {
      setConnecting(false);
    }
  }, [endpoint, image, meshCa]);

  function loadManifest(text: string) {
    setPinNote(null);
    if (!text.trim()) return;
    try {
      setImage(parseManifest(text));
      setPinNote("Image pins loaded from manifest.");
    } catch (e) {
      setPinNote(`Could not read that manifest: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <main className="mx-auto max-w-3xl px-5 py-10 space-y-8">
      <header className="space-y-2">
        <h1 className="text-xl font-semibold">codex-security · attested console</h1>
        <p className="text-sm leading-relaxed" style={{ color: "var(--muted)" }}>
          Verify, in this browser, that the endpoint below is a genuine Intel TDX enclave running
          the image you pinned — and only then submit scans to it. The checks run in WebAssembly on
          this page; no server of ours takes part in them.
        </p>
      </header>

      <section className="panel p-4 space-y-3">
        <label className="block text-sm font-medium">Endpoint</label>
        <input
          className="field mono"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          spellCheck={false}
          disabled={!!result}
        />
        <label className="block text-sm font-medium pt-1">API token</label>
        <input
          className="field mono"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="bearer token for /v1/scans"
          spellCheck={false}
          autoComplete="off"
        />
        <p className="text-xs" style={{ color: "var(--muted)" }}>
          Held in this tab only — never stored, and sent sealed inside the attested channel.
        </p>

        <button
          type="button"
          className="text-xs underline"
          style={{ color: "var(--accent)" }}
          onClick={() => setPinsOpen((v) => !v)}
        >
          {pinsOpen ? "Hide pins" : "Review the pins this page trusts"}
        </button>

        {pinsOpen && (
          <div className="space-y-3 pt-1">
            <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
              These are the out-of-band anchors. They must come from the node image&apos;s published
              manifest and from an operator — never from the endpoint being verified, which is the
              whole point. Paste a different <span className="mono">manifest.json</span> when the
              cluster is rebuilt and its RTMRs change.
            </p>
            {(["mrtd", "rtmr1", "rtmr2"] as const).map((key) => (
              <div key={key}>
                <label className="block text-xs mb-1" style={{ color: "var(--muted)" }}>
                  {key.toUpperCase()}
                </label>
                <input
                  className="field mono text-xs"
                  value={image[key]}
                  onChange={(e) => setImage({ ...image, [key]: e.target.value.trim() })}
                  spellCheck={false}
                  disabled={!!result}
                />
              </div>
            ))}
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--muted)" }}>
                Paste a node image manifest.json to fill the three above
              </label>
              <textarea
                className="field mono text-xs h-20"
                onChange={(e) => loadManifest(e.target.value)}
                placeholder='{"tdx":{"mrtd":"…","rtmr1":"…","rtmr2":"…"}}'
                spellCheck={false}
                disabled={!!result}
              />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: "var(--muted)" }}>
                Mesh CA (pins this specific cluster)
              </label>
              <textarea
                className="field mono text-xs h-24"
                value={meshCa}
                onChange={(e) => setMeshCa(e.target.value)}
                spellCheck={false}
                disabled={!!result}
              />
              {!looksLikePem(meshCa) && (
                <p className="mono text-xs mt-1" style={{ color: "var(--warn)" }}>
                  That does not look like a PEM certificate.
                </p>
              )}
            </div>
            {pinNote && (
              <p className="mono text-xs" style={{ color: "var(--accent)" }}>
                {pinNote}
              </p>
            )}
          </div>
        )}

        {!result && (
          <div className="pt-1">
            <button
              className="btn"
              type="button"
              onClick={() => void connect()}
              disabled={connecting || !endpoint.trim() || !looksLikePem(meshCa)}
            >
              {connecting ? "Verifying…" : "Verify and connect"}
            </button>
          </div>
        )}
      </section>

      <section className="panel p-4 space-y-4">
        <div className="text-sm font-medium">Verification</div>
        <Cascade states={states} failure={failure} />
        {result && (
          <div className="pt-1 space-y-1 text-xs" style={{ color: "var(--muted)" }}>
            <div>
              <span style={{ color: "var(--good)" }}>Verified</span> at{" "}
              {new Date(result.verifiedAt).toLocaleString()} · session{" "}
              <span className="mono">{result.sessionId.slice(0, 12)}</span>
            </div>
            <div className="mono break-all">measurement {result.measurement}</div>
            {result.rtmrsPinned.length > 0 && (
              <div className="mono">registers pinned: {result.rtmrsPinned.join(", ")}</div>
            )}
            {result.warnings.map((w) => (
              <div key={w} className="mono" style={{ color: "var(--warn)" }}>
                {w}
              </div>
            ))}
          </div>
        )}
        {failure && (
          <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
            Nothing below the failed step was checked, so nothing below it is claimed. If the
            browser could not reach the endpoint at all, open it in a tab once and accept its
            certificate — the serving certificate is CDS-issued and attestation-bound, not WebPKI,
            so a browser will not trust it on sight.
          </p>
        )}
      </section>

      {result && api && token && <ScanConsole api={api} />}
      {result && !token && (
        <p className="text-sm" style={{ color: "var(--warn)" }}>
          Enter the API token above to submit scans.
        </p>
      )}

      <footer className="text-xs pt-4" style={{ color: "var(--muted)" }}>
        Verification by{" "}
        <a
          className="underline"
          href="https://github.com/confidential-dot-ai/c8s-verify-js"
          style={{ color: "var(--accent)" }}
        >
          c8s-verify
        </a>
        , running in your browser.
      </footer>
    </main>
  );
}
