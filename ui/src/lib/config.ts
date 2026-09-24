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

// Mesh CA of the cluster below. Re-pinned 2026-09-23 at the production cutover:
// a rebuilt cluster mints a new mesh CA, so this value moves with the RTMRs.
// It comes from an operator who had already attested the node.
const CODEX_MESH_CA = `-----BEGIN CERTIFICATE-----
MIIBqjCCAS+gAwIBAgIQDxMEqKaJeclYafzRtCNvrzAKBggqhkjOPQQDAzAWMRQw
EgYDVQQDEwtjOHMgTWVzaCBDQTAeFw0yNjA5MjMyMjUxNTdaFw0yNzA5MjMyMjUx
NTdaMBYxFDASBgNVBAMTC2M4cyBNZXNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEAgxu9y+2RywKg72kXFqwOsGhciylM0j2Mk68O6F5tfKKKfCrvhImKhvGP8cX
a68HMyNf9BBEwOU8Eu8u5RdTkiwi1bcQGfrCZIyC+aPcpEmkqqVfAQGO4o7Y/xkF
EolMo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU8awySzOJKh+fVDQ++GCP9Z16a4AwCgYIKoZIzj0EAwMDaQAwZgIxANnhaVvq
AvBHrhjdhorIRjRaGl/enhb7d/7IbVfalEAJeFw+ImK1pPiIuEDDaXXTmgIxAM9s
N15n4HB2xT1H2fpoRVPA3gpZKnYkQI8KogsmHDKWJBZbB8D75kIEU4M7D6Tqmw==
-----END CERTIFICATE-----`;

export const PROFILES: Record<string, Profile> = {
  "codex-tdx": {
    id: "codex-tdx",
    label: "codex-tdx (Intel TDX, bare metal)",
    description:
      "The scan API behind the c8s router on an Intel TDX node CVM, with public TLS terminated " +
      "by the router's in-guest ACME sidecar. Pins are the node image's published measurements.",
    endpoint: "https://codex-security-scanner-dev.confidential.ai",
    frontDoor: "acme",
    tdxImage: {
      mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
      rtmr1:
        "168c5937c01d8a0b9228844b65ea01c2ef5ead14f6719ebb135cc9f1a6ea6acda53bad6cd4695ccad2a9d7155c5405b0",
      rtmr2:
        "f8e0a8be2706cdaa6aa96e885998da1652c288548fd0c210e592e7797aae76abecee7d592ee8fd8a9e3a5f8b386ecfc9",
    },
    meshCaPem: CODEX_MESH_CA,
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

/**
 * Development convenience: a bearer token supplied at build time so the scan
 * page can be used without pasting one. Set it in `.env.local`, which is not
 * committed — the token is a live credential for an endpoint that runs billed
 * inference, so it must never enter this repository. When it is unset the page
 * asks for a token as before.
 */
export const DEV_TOKEN = process.env.NEXT_PUBLIC_SCAN_TOKEN ?? "";

/** Copy the pages need that is not a security anchor. */
export const SITE = {
  defaultEndpoint: DEFAULT_PROFILE.endpoint,
  frontDoor: DEFAULT_PROFILE.frontDoor,
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
  image: "ghcr.io/confidential-dot-ai/codex-security",
  imageUrl: "https://github.com/confidential-dot-ai/codex-security/pkgs/container/codex-security",
  digest: "sha256:f67d4ae6b867c528503623af989c8943a8784df8aab9304a058f1e48b473e2ec",
  release: "c8s v0.33.1",
  releaseUrl: "https://github.com/confidential-dot-ai/c8s/releases/tag/v0.33.1",
  /** The upstream findings dashboard that `codex-security serve` ships. */
  dashboardPath: "/dashboard/",
} as const;
