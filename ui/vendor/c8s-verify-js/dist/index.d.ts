import { type AttestationBundle, type AttestationResult, type SnpMinTcb, type VerifyPolicy } from "./verify.js";
import { type XWingKeyPair } from "./keyagreement.js";
import type { Channel } from "./channel.js";
import type { TdxImage } from "./manifest.js";
export { C8sVerifyError } from "./errors.js";
export type { C8sErrorCode } from "./errors.js";
export { BINDING_ATTEST_PQ, TRANSCRIPT_DOMAIN_TAG } from "./identity.js";
export type { MeshIdentityProof } from "./identity.js";
export { verifyAttestation, verifyEvidence } from "./verify.js";
export type { VerifyPolicy, AttestationBundle, AttestationResult, EvidenceResult, VerifyEvidenceOptions, CertInfo, WorkloadInfo, SnpMinTcb, } from "./verify.js";
export { OID_MATCHED_WORKLOAD, parseMatchedWorkload, parseAllowlist, resolveWorkload, allowlistDigestHex, } from "./workload.js";
export type { MatchedWorkload, AllowlistDocument, AllowlistWorkload } from "./workload.js";
export { parseImageManifest } from "./manifest.js";
export type { TdxImage } from "./manifest.js";
export { decodePEM, decodeOnePEM, encodePEM } from "./pem.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence, AzTdxEvidence, TdxEvidence } from "./hcl.js";
export interface C8sClientOptions {
    baseUrl: string;
    measurements: string[];
    platform?: string;
    /**
     * SEV-SNP processor generation ("milan" | "genoa" | "turin"), pinned out of
     * band; `platform: "snp"` only. Optional — the generation selects the VCEK
     * chain the report is verified against, so an unpinned one is authenticated
     * by that chain rather than believed. See `VerifyPolicy.generation`.
     */
    generation?: string;
    requireFreshness?: boolean;
    /**
     * Mesh CA pinned out of band — the specific-cluster anchor. At least one of
     * `meshCaPem` and `allowlist` is required; both together is fine.
     *
     * Multiple PEM blocks mean *each block is independently trusted* as an
     * anchor: the identity proof selects whichever one it names. That is
     * occasionally what you want during a CA rotation, and a footgun the rest
     * of the time, so prefer a single block.
     */
    meshCaPem?: string;
    /**
     * Exact canonical allowlist bytes, pinned out of band — the
     * deployment-class anchor. A string is UTF-8-encoded verbatim, never
     * parsed-and-reserialized. Requires the mesh leaf's matched-workload stamp
     * to commit SHA-256 of exactly these bytes and resolves the stamped name in
     * the document; the mesh CA is then derived from the identity transcript's
     * commitment instead of pinned (`attestation.trustClass` reports which
     * verdict you got).
     */
    allowlist?: Uint8Array | string;
    /**
     * Expected matched-workload name on the mesh leaf. Optional; enforced
     * against the CA-vouched stamp after the chain check, which either anchor
     * provides.
     */
    workloadName?: string;
    at?: Date;
    fetch?: typeof fetch;
    wellKnownPrefix?: string;
    /**
     * Expected TDX RTMR[3] (96 hex chars), pinned out of band. Optional but
     * strongly recommended: `measurements` proves the node runs the audited
     * build, not that it is *your* node — the images are reproducible, so anyone
     * can stand up an instance with the same launch digest. RTMR[3] carries the
     * operator key bound at launch, which is unique to a deployment and, unlike
     * `meshCaPem`, survives reinstalls and image rebuilds. Requires
     * `platform: "tdx"`.
     */
    expectedRtmr3?: string;
    /**
     * The complete TDX guest-image pin: the mrtd+rtmr1+rtmr2 tuple published
     * with the image build (feed the manifest file to `parseImageManifest`).
     * `measurements` alone pins only MRTD — the TDVF firmware — while the guest
     * kernel and rootfs land in RTMR[1]/RTMR[2], so only the tuple identifies
     * the image. Required for a TDX deployment-class verdict (no `meshCaPem`);
     * strongly recommended otherwise. Requires `platform: "tdx"`.
     */
    tdxImage?: TdxImage;
    /**
     * Minimum SEV-SNP TCB floor, pinned from AMD security bulletins. A genuine,
     * correctly-measured guest on platform firmware below the floor is
     * rejected (`tcb_denied`). SNP platforms only. See `VerifyPolicy.minTcb`.
     */
    minTcb?: SnpMinTcb;
    /**
     * DER AMD KDS CRL for the deployment's processor generation, fetched or
     * stapled by the caller. Supplying it makes endorsement-key revocation part
     * of every connection's verdict. SNP platforms only. See
     * `VerifyPolicy.snpCrl`.
     */
    snpCrl?: Uint8Array;
    /**
     * Require the revocation collateral to be verified for the verdict to pass
     * (production policy). Requires `snpCrl`. See
     * `VerifyPolicy.requireCollateral`.
     */
    requireCollateral?: boolean;
}
export interface RequestInit {
    method?: string;
    /**
     * Request headers: a plain record, or ordered [name, value] pairs when a
     * field repeats (Cookie). Duplicate pairs reach the backend intact.
     */
    headers?: Record<string, string> | [string, string][];
    body?: string | Uint8Array;
}
export interface TunnelResponse {
    status: number;
    /** First value of each field. Use headersList for repeated fields. */
    headers: Record<string, string>;
    /** Every header field in response order as [name, value] pairs. */
    headersList: [string, string][];
    bytes: Uint8Array;
    text: () => string;
}
interface SessionOptions {
    baseUrl: string;
    prefix: string;
    fetch: typeof fetch;
    channel: Channel;
    sessionId: string;
    attestation: AttestationResult;
}
export declare class C8sClient {
    readonly baseUrl: string;
    readonly prefix: string;
    readonly fetch: typeof fetch;
    /** Verification policy applied to every connection. */
    readonly policy: VerifyPolicy;
    constructor(opts: C8sClientOptions);
    private _url;
    /**
     * POST the client-first attest-pq request — the fresh nonce and our X-Wing
     * encapsulation key — and return the bundle. There is no fallback, alias,
     * or version parameter: the endpoint is the version selector, and a server
     * that does not serve it is a server this client cannot verify.
     */
    fetchAttestation(nonce: Uint8Array, keyPair: XWingKeyPair): Promise<AttestationBundle>;
    /**
     * Run the full flow in one round trip: send our key exchange, verify the
     * returned evidence (which commits both sides of it), decapsulate, and
     * derive the over-encrypted channel. The session is live on return.
     */
    connect(): Promise<Session>;
}
/**
 * An established, verified, over-encrypted session with the LB.
 */
export declare class Session {
    readonly baseUrl: string;
    readonly prefix: string;
    private readonly _fetch;
    readonly channel: Channel;
    readonly sessionId: string;
    /** Verification result: measurement, platform, cert info, warnings, ... */
    readonly attestation: AttestationResult;
    constructor(o: SessionOptions);
    /**
     * Channel-binding exporter (32 bytes): derived by both ends from the shared
     * secret under the attested transcript, never sent on the wire. The sidecar
     * hands the backend the same value as the X-C8s-Exporter header, so an
     * application can bind bearer credentials to this exact channel.
     */
    get exporter(): Uint8Array;
    /**
     * Make an over-encrypted request to the LB. The entire request — method, path,
     * headers, and body — is sealed with AES-256-GCM and sent to the tunnel
     * endpoint, so a TLS-terminating proxy in front of the LB sees only ciphertext.
     * The LB enclave decrypts it, forwards the plaintext request to the backend
     * (over the cluster raTLS mesh), and seals the response back.
     */
    fetch(path: string, init?: RequestInit): Promise<TunnelResponse>;
}
//# sourceMappingURL=index.d.ts.map