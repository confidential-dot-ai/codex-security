"use client";

// Attestation, broken into the phases the console displays. Every security
// decision is made by c8s-verify's own primitives — this module only decides
// what to *show*, and never marks a step passed that the library has not
// already checked.
//
// The console deliberately connects rather than merely verifying: C8sClient
// .connect() binds a fresh nonce and the derived channel keys into the
// quote's report_data, so a replayed quote cannot carry a session. Every scan
// request then rides inside that channel (see api.ts), which is a stronger
// claim than "attest once, then call the endpoint normally".

import { C8sClient, C8sVerifyError, type Session } from "c8s-verify";
import type { TdxImagePin } from "./config";

export type StepId = "connect" | "dcap" | "mrtd" | "rtmr1" | "rtmr2" | "meshca" | "channel";
export type StepState = "idle" | "active" | "pass" | "fail" | "skip";

export interface Step {
  id: StepId;
  label: string;
  detail: string;
}

/** Presented in order; the cascade resolves top to bottom. */
export const STEPS: Step[] = [
  {
    id: "connect",
    label: "Fresh nonce exchanged",
    detail: "The browser generates a nonce the cluster must echo inside signed hardware evidence.",
  },
  {
    id: "dcap",
    label: "Intel TDX quote verified",
    detail: "The DCAP certificate chain is checked in WebAssembly, in this tab.",
  },
  {
    id: "mrtd",
    label: "MRTD matches the pinned image",
    detail: "The firmware launch measurement. On TDX this covers TDVF only, which is why the next two matter.",
  },
  {
    id: "rtmr1",
    label: "RTMR[1] matches — guest kernel",
    detail: "Without this the kernel is unmeasured and the image is substitutable.",
  },
  {
    id: "rtmr2",
    label: "RTMR[2] matches — kernel command line",
    detail: "Carries the dm-verity root hash, which pins the entire root filesystem.",
  },
  {
    id: "meshca",
    label: "Serving certificate chains to the pinned mesh CA",
    detail: "Binds this specific cluster, not merely some genuine TDX machine.",
  },
  {
    id: "channel",
    label: "Over-encrypted channel established",
    detail: "Requests are sealed to the attested enclave; a TLS-terminating proxy sees only ciphertext.",
  },
];

export interface AttestResult {
  session: Session;
  measurement: string;
  rtmrsPinned: string[];
  sessionId: string;
  verifiedAt: string;
  warnings: string[];
}

export class AttestError extends Error {
  /** The step the cascade should mark failed. Later steps stay unchecked. */
  readonly step: StepId;
  readonly code?: string;
  constructor(step: StepId, message: string, code?: string) {
    super(message);
    this.step = step;
    this.code = code;
  }
}

/**
 * Map a library failure onto the furthest step it is documented to have
 * reached. Verification is ordered — nonce echo, then the hardware chain, then
 * the measurement pins, then the CA — so an error code names how far it got.
 * Anything unrecognised is attributed to the hardware check rather than to a
 * later step, so the cascade never overstates what was proven.
 */
function stepForFailure(code: string | undefined): StepId {
  switch (code) {
    case "nonce_mismatch":
    case "version_mismatch":
    case "http_error":
    case "network_error":
      return "connect";
    case "measurement_mismatch":
      return "mrtd";
    case "rtmr_mismatch":
      return "rtmr1";
    case "chain_error":
    case "ca_mismatch":
    case "identity_error":
      return "meshca";
    case "channel_error":
    case "handshake_error":
      return "channel";
    default:
      return "dcap";
  }
}

export interface AttestOptions {
  endpoint: string;
  tdxImage: TdxImagePin;
  meshCaPem: string;
  /** Called as each step resolves, so the cascade animates. */
  onStep?: (id: StepId, state: StepState) => void;
}

export async function attest(opts: AttestOptions): Promise<AttestResult> {
  const mark = opts.onStep ?? (() => {});
  const client = new C8sClient({
    baseUrl: opts.endpoint.replace(/\/+$/, ""),
    platform: "tdx",
    // mrtd joins the measurement allowlist; rtmr1/rtmr2 are compared exactly.
    measurements: [opts.tdxImage.mrtd],
    tdxImage: opts.tdxImage,
    meshCaPem: opts.meshCaPem,
    requireFreshness: true,
  });

  for (const id of ["connect", "dcap", "mrtd", "rtmr1", "rtmr2", "meshca", "channel"] as StepId[]) {
    mark(id, "idle");
  }
  mark("connect", "active");

  let session: Session;
  try {
    // One call does the whole flow; the library refuses to hand back a session
    // unless every check above it passed.
    session = await client.connect();
  } catch (error) {
    const code = error instanceof C8sVerifyError ? error.code : undefined;
    const step = stepForFailure(code);
    const order: StepId[] = ["connect", "dcap", "mrtd", "rtmr1", "rtmr2", "meshca", "channel"];
    for (const id of order) {
      if (id === step) break;
      mark(id, "pass");
    }
    mark(step, "fail");
    throw new AttestError(
      step,
      error instanceof Error ? error.message : String(error),
      code,
    );
  }

  for (const id of ["connect", "dcap", "mrtd", "rtmr1", "rtmr2", "meshca", "channel"] as StepId[]) {
    mark(id, "pass");
  }

  const attestation = session.attestation as unknown as {
    measurement?: string;
    rtmrsPinned?: string[];
    warnings?: string[];
  };
  return {
    session,
    measurement: attestation.measurement ?? "",
    rtmrsPinned: attestation.rtmrsPinned ?? [],
    sessionId: session.sessionId,
    verifiedAt: new Date().toISOString(),
    warnings: attestation.warnings ?? [],
  };
}
