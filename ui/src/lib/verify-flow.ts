"use client";

// The verification flow, broken into UI-visible phases, but with every
// security decision made by the c8s-verify library's own primitives:
//
//   phase 1  nonce + attestation exchange   (C8sClient.fetchAttestation)
//   phase 2  evidence verification          (verifyAttestation: nonce echo,
//            mesh chain, DCAP chain, MRTD/RTMR pins, report_data, leaf PoP)
//   phase 3  hybrid PQ handshake            (clientKeyAgreement + handshake
//            endpoint -> Session, exactly as C8sClient.connect() does)
//
// Phase granularity exists so the on-screen cascade resolves live. On failure
// the cascade marks only what the library is documented to have already
// checked, never more (see mapVerifyFailure).

import {
  C8sClient,
  C8sVerifyError,
  generateNonce,
  verifyAttestation,
  Session,
  type AttestationBundle,
  type AttestationResult,
} from "c8s-verify";
// Subpath imports: the same primitives C8sClient.connect() uses internally. We
// drive them directly so each phase can be shown as it resolves, rather than
// reporting one opaque success or failure at the end.
import { deriveChannel, generateXWingKeyPair, xwingDecapsulate } from "c8s-verify/keyagreement";
import { bytesToBase64Url } from "c8s-verify/base64";


export type StepId = "nonce" | "dcap" | "mrtd" | "rtmr1" | "rtmr2" | "meshca" | "channel";

export type StepState = "idle" | "active" | "pass" | "fail" | "skip";

export interface Measured {
  mrtd: string;
  rtmr0?: string;
  rtmr1?: string;
  rtmr2?: string;
  rtmr3?: string;
}

export interface VerifySuccess {
  attestation: AttestationResult;
  session: Session;
  measured: Measured;
  endpoint: string;
  verifiedAt: string;
  nonceB64u: string;
  sessionId: string;
}

export class VerificationError extends Error {
  readonly code?: string;
  readonly step: StepId;
  constructor(step: StepId, message: string, code?: string) {
    super(message);
    this.step = step;
    this.code = code;
  }
}

export function normalizeBaseUrl(raw: string): string | null {
  let s = String(raw || "").trim();
  if (!s) return null;
  if (!/^https?:\/\//.test(s)) s = "https://" + s;
  try {
    return new URL(s).origin;
  } catch {
    return null;
  }
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e ?? "unknown error"));

const codeOf = (e: unknown): string | undefined =>
  e instanceof C8sVerifyError ? e.code : undefined;

/**
 * Map a phase-2 failure to the presented cascade, using the check order
 * verifyAttestation is documented to run:
 *
 *   nonce echo -> version/identity shape -> mesh CA chain ->
 *   [WASM: DCAP chain+signature, report_data] ->
 *   MRTD allowlist -> RTMR[1] -> RTMR[2] -> freshness -> leaf proof-of-possession
 *
 * A step is marked "pass" only when the library had already enforced it before
 * the failure point; unreached steps are marked "skip". Nothing below a failure
 * is ever claimed.
 */
function mapVerifyFailure(
  e: unknown,
  onStep: (id: StepId, state: StepState, detail?: string) => void,
): VerificationError {
  const code = codeOf(e);
  const msg = errText(e);
  const ALL: StepId[] = ["nonce", "dcap", "mrtd", "rtmr1", "rtmr2", "meshca"];
  const apply = (failed: StepId, passed: StepId[]) => {
    for (const s of ALL) {
      if (s === failed) onStep(s, "fail");
      else if (passed.includes(s)) onStep(s, "pass");
      else onStep(s, "skip");
    }
    return new VerificationError(failed, msg, code);
  };

  if (code === "nonce_mismatch") return apply("nonce", []);
  if (code === "report_data_mismatch") return apply("nonce", ["meshca", "dcap"]);
  // The bundle did not echo the X-Wing key this browser sent: the evidence is
  // not bound to this session, whatever else it proves.
  if (code === "key_binding") return apply("nonce", ["meshca", "dcap"]);

  if (code === "invalid_cert") return apply("meshca", ["nonce"]);
  if (code === "identity_binding") {
    const preHardware =
      /has version|omitted or malformed identity_proof|omitted cds_cert_pem|does not name any pinned mesh CA|no served CA certificate matches|requires a served leaf|contains no PEM CERTIFICATE/i.test(
        msg,
      );
    return preHardware
      ? apply("meshca", ["nonce"])
      : apply("meshca", ["nonce", "dcap", "mrtd", "rtmr1", "rtmr2"]);
  }

  if (code === "verification_failed") return apply("dcap", ["nonce", "meshca"]);

  if (code === "measurement_denied" || code === "measurement_incomplete")
    return apply("mrtd", ["nonce", "meshca", "dcap"]);
  if (code === "rtmr_denied") {
    const which: StepId = /rtmr_2|RTMR\[2\]/.test(msg) ? "rtmr2" : "rtmr1";
    const passed: StepId[] = ["nonce", "meshca", "dcap", "mrtd"];
    if (which === "rtmr2") passed.push("rtmr1");
    return apply(which, passed);
  }

  // Anything else in phase 2: fail the DCAP step conservatively (it is the
  // phase's umbrella check) and claim nothing downstream.
  return apply("dcap", ["nonce", "meshca"]);
}

function measuredFromClaims(a: AttestationResult): Measured {
  const pd = (a.claims?.platform_data ?? {}) as Record<string, unknown>;
  const hex = (v: unknown) => (typeof v === "string" ? v.toLowerCase() : undefined);
  return {
    mrtd: a.measurement,
    rtmr0: hex(pd.rtmr_0),
    rtmr1: hex(pd.rtmr_1),
    rtmr2: hex(pd.rtmr_2),
    rtmr3: hex(pd.rtmr_3),
  };
}


/** How long any single request in the flow may take. */
const REQUEST_TIMEOUT_MS = 20_000;

/**
 * A failure here happened before any attestation ran, so it is a connection
 * problem and must be reported as one. The overwhelmingly common cause is the
 * serving certificate: it is CDS-issued and attestation-bound, not WebPKI, so
 * the browser refuses the origin until the user has opened it in a tab once and
 * accepted it.
 */
function reachabilityHint(baseUrl: string, e: unknown): string {
  const msg = errText(e);
  const timedOut = e instanceof DOMException && e.name === "TimeoutError";
  return timedOut
    ? `${baseUrl} accepted the connection but did not answer within ${REQUEST_TIMEOUT_MS / 1000}s. ` +
        "Nothing was verified."
    : `the browser could not reach ${baseUrl} (${msg}). Open ${baseUrl} in a tab once and accept ` +
        "its certificate — it is CDS-issued and attestation-bound, not WebPKI, so the browser " +
        "blocks the request before any attestation can run.";
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Run the full verification + channel establishment against `endpoint`,
 * reporting cascade progress through `onStep`.
 */
export async function runVerification(
  endpoint: string,
  pins: { mrtd: string; rtmr1: string; rtmr2: string },
  meshCaPem: string,
  onStep: (id: StepId, state: StepState, detail?: string) => void,
  animate = true,
  platform = "tdx",
): Promise<VerifySuccess> {
  const baseUrl = normalizeBaseUrl(endpoint);
  if (!baseUrl) {
    onStep("nonce", "fail", "enter a valid endpoint URL");
    throw new VerificationError("nonce", "Enter a valid endpoint URL.");
  }

  // Every request this flow makes gets a deadline. Without one, a browser that
  // has not been shown the CDS certificate, or a router that accepts the
  // connection and never answers, leaves the cascade spinning with nothing to
  // report — which is worse than a plain failure.
  const timedFetch: typeof fetch = (input, init) =>
    fetch(input, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });

  const client = new C8sClient({
    baseUrl,
    fetch: timedFetch,
    platform,
    requireFreshness: true,
    // MRTD alone pins only the TDVF firmware; the tuple pins the whole guest
    // image, enforced inside the verifier (fails closed on any register).
    measurements: [pins.mrtd],
    tdxImage: { mrtd: pins.mrtd, rtmr1: pins.rtmr1, rtmr2: pins.rtmr2 },
    // The specific-cluster anchor, pinned out of band, never fetched from the
    // endpoint under test.
    meshCaPem,
  });

  // -- Phase 1: fresh nonce -> attestation bundle ------------------------
  onStep("nonce", "active");
  const nonce = generateNonce();
  const nonceB64u = bytesToBase64Url(nonce);
  // Client-first: our X-Wing encapsulation key goes out with the nonce, so the
  // enclave signs evidence that commits to both sides of the key exchange. One
  // round trip, and a replayed quote cannot carry this session.
  const keyPair = await generateXWingKeyPair();
  let bundle: AttestationBundle;
  try {
    bundle = await client.fetchAttestation(nonce, keyPair);
  } catch (e) {
    onStep("nonce", "fail", reachabilityHint(baseUrl, e));
    throw new VerificationError("nonce", reachabilityHint(baseUrl, e), codeOf(e) ?? "network_error");
  }
  // Presentational echo check (verifyAttestation enforces it again, and the
  // report_data check below is what binds the nonce into hardware evidence).
  if (bundle?.nonce !== nonceB64u) {
    onStep("nonce", "fail", "the endpoint did not echo this session's nonce");
    throw new VerificationError(
      "nonce",
      "attestation bundle nonce does not match the nonce this browser generated",
      "nonce_mismatch",
    );
  }

  // -- Phase 2: verify evidence + every pin ------------------------------
  onStep("dcap", "active");
  let attestation: AttestationResult;
  try {
    attestation = await verifyAttestation(bundle, nonce, client.policy, keyPair.ek);
  } catch (e) {
    throw mapVerifyFailure(e, onStep);
  }

  const measured = measuredFromClaims(attestation);
  const passes: [StepId, string][] = [
    [
      "nonce",
      `report_data binds nonce ${nonceB64u.slice(0, 10)}… + session keys + mesh leaf + issuing CA`,
    ],
    ["dcap", "TDX quote signature + PCK chain to the Intel SGX Root CA, verified in WASM"],
    ["mrtd", measured.mrtd],
    ["rtmr1", measured.rtmr1 ?? "-"],
    ["rtmr2", measured.rtmr2 ?? "-"],
    [
      "meshca",
      `mesh leaf ${attestation.cert.sha256.slice(0, 16)}… chains to the pinned ${
        attestation.cert.issuerCN ?? "mesh CA"
      } → verdict: ${attestation.trustClass}`,
    ],
  ];
  for (const [id, detail] of passes) {
    onStep(id, "pass", detail);
    if (animate) await sleep(90);
  }

  // -- Phase 3: X-Wing decapsulation -> AES-256-GCM channel --------------
  onStep("channel", "active");
  try {
    // No network call here: the enclave's ciphertext arrived inside the signed
    // evidence that phase 2 verified, so only the enclave that produced it can
    // hold the other end of this key.
    const sharedSecret = await xwingDecapsulate(keyPair, attestation.keyExchange.xwingCt);
    const channel = await deriveChannel(
      "client",
      sharedSecret,
      attestation.keyAgreementContext,
      attestation.keyExchange.sessionId,
    );
    const sessionId = bundle.session_id;
    const session = new Session({
      baseUrl: client.baseUrl,
      prefix: client.prefix,
      fetch: globalThis.fetch.bind(globalThis),
      channel,
      sessionId,
      attestation,
    });
    onStep("channel", "pass", `X-Wing (ML-KEM-768 + X25519) → AES-256-GCM · session ${sessionId}`);
    return {
      attestation,
      session,
      measured,
      endpoint: baseUrl,
      verifiedAt: new Date().toISOString(),
      nonceB64u,
      sessionId,
    };
  } catch (e) {
    onStep("channel", "fail");
    throw new VerificationError(
      "channel",
      `evidence verified, but the channel could not be derived: ${errText(e)}`,
      codeOf(e) ?? "channel_error",
    );
  }
}
