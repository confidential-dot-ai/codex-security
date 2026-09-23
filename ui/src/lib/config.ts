// Deployment-specific pins. Everything here is an *out-of-band* anchor: it is
// what the browser trusts before it has spoken to the cluster, so it must come
// from the image build (the published manifest.json) and from an operator, not
// from the endpoint being verified.
//
// A profile is a starting point, not a lock — the console lets an operator
// paste a different manifest and mesh CA at runtime, which is the honest
// workflow when a cluster is rebuilt and its RTMRs change.

export interface TdxImagePin {
  /** Firmware launch measurement. On TDX this covers TDVF only. */
  mrtd: string;
  /** Guest kernel. */
  rtmr1: string;
  /** Kernel command line, which carries the dm-verity root hash. */
  rtmr2: string;
}

export interface Profile {
  id: string;
  label: string;
  description: string;
  /** Base URL of the c8s router fronting the scan API. */
  endpoint: string;
  /** The guest image tuple, from the node image's published manifest.json. */
  tdxImage: TdxImagePin;
  /**
   * Mesh CA, pinned out of band. c8s-verify requires at least one of a mesh CA
   * (specific-cluster anchor) or the canonical allowlist bytes
   * (deployment-class anchor); a CA pinned by an operator is the stronger one,
   * and it is why this file exists rather than fetching it from the endpoint.
   */
  meshCaPem: string;
}

// Mesh CA of the cluster below. Pinned 2026-09-23 from the operator's own
// `c8s get-kubeconfig`-attested session, not from an unverified fetch.
const CODEX_DEV_MESH_CA = `-----BEGIN CERTIFICATE-----
MIIBqTCCAS+gAwIBAgIQWugF+peffBYSU4QiXXyVhjAKBggqhkjOPQQDAzAWMRQw
EgYDVQQDEwtjOHMgTWVzaCBDQTAeFw0yNjA5MjMwMTE5MDJaFw0yNzA5MjMwMTE5
MDJaMBYxFDASBgNVBAMTC2M4cyBNZXNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEH+VFJRtx4SPkbd+b9bLoNqWxrUvqCk1pV7eT24KBpRg8HBktg0aaHfOtAvrR
td32Ig1N5xm1CrDDKjwaAGTBxvo1uJxMYtNSokFwZLhSKSLMNHWKiMoruTfLfsLq
lkEQo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUmVlpP+VmBOH8O/a3VefcZn1cisgwCgYIKoZIzj0EAwMDaAAwZQIxAK25fZTV
ooCmhjV/JGf4bPr7r2Fc+sco5ps2y2ffvcfpwGVS/xONYJeAQ5WudiAhIwIwB84+
74PG01viW4twsJVthisgdvKfYVRtJnwH3VIcGxStboDrxVofOS6+qevO4Irp
-----END CERTIFICATE-----`;

export const PROFILES: Record<string, Profile> = {
  "codex-dev": {
    id: "codex-dev",
    label: "codex-dev (Intel TDX, bare metal)",
    description:
      "The scan API behind the c8s router on an Intel TDX node CVM. " +
      "Pins are the node image's published measurements.",
    endpoint: "https://15.204.104.35:30443",
    tdxImage: {
      mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
      rtmr1:
        "c7a87124d0c5943226b95dfeb56231f6512794e7fa50efc0578a1dbcab10bfa89b47a93ba6b08617ede02a22c0a5c4f7",
      rtmr2:
        "f26bcbd2e724a76d059ead9cd9592774bf202782b11606ce298b7d69e163a4c11e5f4add8703bc3ebf45340088636310",
    },
    meshCaPem: CODEX_DEV_MESH_CA,
  },
};

export const DEFAULT_PROFILE =
  process.env.NEXT_PUBLIC_DEPLOYMENT && PROFILES[process.env.NEXT_PUBLIC_DEPLOYMENT]
    ? PROFILES[process.env.NEXT_PUBLIC_DEPLOYMENT]!
    : PROFILES["codex-dev"]!;

const HEX96 = /^[0-9a-f]{96}$/;

/**
 * Read a TDX image tuple out of a node image's `manifest.json`. The same file
 * `c8s verify --image-manifest` and `c8s install --measurements/--rtmrs` read,
 * so an operator can paste it verbatim instead of transcribing three hashes.
 */
export function parseManifest(text: string): TdxImagePin {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("not valid JSON");
  }
  const tdx = (doc as { tdx?: Record<string, unknown> } | null)?.tdx;
  if (!tdx) throw new Error('no "tdx" section — is this a TDX node image manifest?');
  const pin: Record<string, string> = {};
  for (const key of ["mrtd", "rtmr1", "rtmr2"] as const) {
    const value = tdx[key];
    if (typeof value !== "string" || !HEX96.test(value)) {
      throw new Error(`tdx.${key} is missing or not 96 lowercase hex characters`);
    }
    pin[key] = value;
  }
  return pin as unknown as TdxImagePin;
}

export function looksLikePem(text: string): boolean {
  return (
    text.includes("-----BEGIN CERTIFICATE-----") &&
    text.includes("-----END CERTIFICATE-----")
  );
}
