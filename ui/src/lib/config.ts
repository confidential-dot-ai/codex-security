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
  /**
   * Which credential terminates public TLS at the router. `cds` is a mesh-issued,
   * attestation-bound certificate a browser will not trust on sight; `acme` is a
   * WebPKI certificate issued to an in-guest sidecar, so the key is still
   * TEE-held. The endpoint commits this into the attestation transcript, so the
   * value here is only what the page expects — the verdict reports what was
   * actually proven.
   */
  frontDoor: "cds" | "acme";
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

// Mesh CA of the cluster below, pinned 2026-09-23 from an operator session
// that had already attested the node, not from an unverified fetch.
const CODEX_TDX_MESH_CA = `-----BEGIN CERTIFICATE-----
MIIBqTCCAS+gAwIBAgIQDwFa3rbWAX/Q9O+vT+Ci6TAKBggqhkjOPQQDAzAWMRQw
EgYDVQQDEwtjOHMgTWVzaCBDQTAeFw0yNjA5MjMwNDMwMTRaFw0yNzA5MjMwNDMw
MTRaMBYxFDASBgNVBAMTC2M4cyBNZXNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEkKjY1skCZNhMSgN2DCmRW9lOSxG+0pQ6HNr09v9CqlgXm3YDvE9V8XssMLna
K8z53IHIwX3M4y9zJlEeiv/kEBsUoB95rfHytNgB+R5Mp8j2T5n6C36OmxDYmX6s
atXyo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUQUNZf7feLOUEdj4SbY95oULRD6QwCgYIKoZIzj0EAwMDaAAwZQIxALY/0wnH
W/OwswGZE1UZDnA0N0AwaLL+mxfrGXPUp+3oRq8YV6MafB8EuoxAPMwiggIwCrgj
TlKCWHwYJ1n3LKb38QwPtGGlUznyHCEP5oBnCeFuodtIdf4/V03chYz34o6A
-----END CERTIFICATE-----`;

export const PROFILES: Record<string, Profile> = {
  "codex-tdx": {
    id: "codex-tdx",
    label: "codex-tdx (Intel TDX, bare metal)",
    description:
      "The scan API behind the c8s router on an Intel TDX node CVM. " +
      "Pins are the node image's published measurements.",
    endpoint: "https://15.204.104.35:30443",
    frontDoor: "cds",
    tdxImage: {
      mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
      rtmr1:
        "3b260925fec6a0553b9a6aecf223a6ed1ddcbbee17df0b0e5c8bc056b0751c8530a83e71ed5b7ef9ff142ae842cdcecd",
      rtmr2:
        "eb120e4c57137f7a3f72c6ca3403d6f26da427df4ddcf0ed2580b72ab08a7a6078034c728a78e1153f77f199c9bbf615",
    },
    meshCaPem: CODEX_TDX_MESH_CA,
  },
  // The same cluster once the router serves a WebPKI certificate through the
  // in-guest ACME sidecar. Same hardware, same image, so the pins and the mesh
  // CA are unchanged; what changes is the credential terminating public TLS,
  // which the endpoint commits into the attestation transcript as
  // front_door_mode. Select with NEXT_PUBLIC_DEPLOYMENT=codex-acme.
  "codex-acme": {
    id: "codex-acme",
    label: "codex-tdx behind the ACME front door (Intel TDX, bare metal)",
    description:
      "The scan API behind the c8s router, with public TLS terminated by the in-guest ACME " +
      "sidecar. The serving key stays TEE-held, so attest-lb is still served.",
    endpoint: "https://codex-security-scanner-dev.confidential.ai",
    frontDoor: "acme",
    tdxImage: {
      mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
      rtmr1:
        "3b260925fec6a0553b9a6aecf223a6ed1ddcbbee17df0b0e5c8bc056b0751c8530a83e71ed5b7ef9ff142ae842cdcecd",
      rtmr2:
        "eb120e4c57137f7a3f72c6ca3403d6f26da427df4ddcf0ed2580b72ab08a7a6078034c728a78e1153f77f199c9bbf615",
    },
    meshCaPem: CODEX_TDX_MESH_CA,
  },
};

export const DEFAULT_PROFILE =
  process.env.NEXT_PUBLIC_DEPLOYMENT && PROFILES[process.env.NEXT_PUBLIC_DEPLOYMENT]
    ? PROFILES[process.env.NEXT_PUBLIC_DEPLOYMENT]!
    : PROFILES["codex-tdx"]!;

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

/** Convenience aliases for the active profile, mirroring c8s-verify-poc. */
export const PINS: TdxImagePin = DEFAULT_PROFILE.tdxImage;
export const MESH_CA_PEM: string = DEFAULT_PROFILE.meshCaPem;

/** Copy the pages need that is not a security anchor. */
export const SITE = {
  defaultEndpoint: DEFAULT_PROFILE.endpoint,
  frontDoor: DEFAULT_PROFILE.frontDoor,
  platformLabel: "Intel TDX, bare metal (DCAP)",
  repo: "https://github.com/confidential-dot-ai/codex-security",
  c8s: "https://github.com/confidential-dot-ai/c8s",
  verifyLib: "https://github.com/confidential-dot-ai/c8s-verify-js",
} as const;

/**
 * What is running behind the endpoint. Not a security anchor — the pins above
 * are — but the strings an operator publishes alongside them, so a reader can
 * go and look at the same image. The registry digest is what GHCR serves and
 * what the cluster allowlist pins; it differs from any digest computed locally.
 */
export const DEPLOYMENT = {
  image: "ghcr.io/confidential-dot-ai/codex-security:scan-api",
  digest: "sha256:f67d4ae6b867c528503623af989c8943a8784df8aab9304a058f1e48b473e2ec",
  release: "c8s v0.33.1 (ec67bd8 + #691)",
  releaseLong:
    "c8s v0.33.1 (ec67bd8) plus the operator-scope guard fix (c8s#691), a Cilium postStart fix, and a deployment-baked router upstream. Node image built 2026-09-23, locked profile, Intel TDX node CVM, Kubernetes v1.36.4+rke2r1.",
  kubernetes: "v1.36.4+rke2r1",
} as const;
