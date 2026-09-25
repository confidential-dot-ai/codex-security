import type { Evidence } from "./hcl.js";
import { type MeshIdentityProof } from "./identity.js";
import { type TdxImage } from "./manifest.js";
/**
 * Minimum SEV-SNP TCB floor: security patch levels (SPLs) the reported TCB
 * must meet or exceed, component by component. Values come from AMD security
 * bulletins for the deployment's processor generation; `fmc` exists only on
 * Turin and a floor requiring it rejects reports that do not carry it.
 */
export interface SnpMinTcb {
    bootloader: number;
    tee: number;
    snp: number;
    microcode: number;
    fmc?: number;
}
export interface VerifyPolicy {
    /** accepted launch digests (hex sha-384) */
    measurements: string[];
    /** default "snp"; also "az-snp" | "az-tdx" | "tdx" (bare-metal Intel TDX) */
    platform?: string;
    /**
     * SEV-SNP processor generation ("milan" | "genoa" | "turin"), pinned out of
     * band. `platform: "snp"` only — az-snp auto-detects it from the report
     * CPUID and TDX has no such concept, so a pin elsewhere would enforce
     * nothing and is rejected rather than dropped.
     *
     * Optional because the generation is *authenticated*, not merely asserted:
     * it selects the VCEK/ASK/ARK chain the report is verified against, so a
     * responder that declares the wrong one fails its own chain check. Left
     * unset, the value is taken from the response — the only responder-supplied
     * field that reaches a verification decision. Pinning it turns a mismatch
     * into a stated policy decision instead of a chain failure, and documents
     * which silicon the caller believes it is talking to.
     */
    generation?: string;
    /** default true: report_data must bind the selected session transcript */
    requireFreshness?: boolean;
    /**
     * Mesh CA pinned out of band. Optional: the required anchor is this pin OR
     * `allowlist`. When absent, the anchor is the transcript-committed CA
     * selected from the served chain — the identity transcript authenticates
     * the choice, and the verdict is deployment-class rather than
     * specific-cluster (see {@link AttestationResult.trustClass}).
     */
    meshCaPem?: string;
    /**
     * Exact canonical allowlist bytes (`GET /allowlist` response, or the output
     * of the canonicalization tool), pinned out of band. A string is
     * UTF-8-encoded verbatim, never parsed-and-reserialized — the stamp commits
     * SHA-256 over these exact bytes.
     *
     * Pinning it requires the mesh leaf to carry a matched-workload stamp whose
     * allowlist digest equals SHA-256 of these bytes, and resolves the stamped
     * name in this document. Serves as the trust anchor when `meshCaPem` is
     * absent.
     */
    allowlist?: Uint8Array | string;
    /**
     * Expected matched-workload name. Requires the mesh leaf to carry a stamp
     * naming exactly this workload. The stamp is CA-vouched, so this is
     * enforced only after the chain check — which either anchor provides.
     */
    workloadName?: string;
    /** validity reference time (default now) */
    at?: Date;
    /**
     * Expected TDX RTMR[3] (96 hex chars), pinned out of band. Optional.
     *
     * `measurements` pins the *code*, but the c8s images are open source and
     * reproducible, so a valid launch digest only proves "a genuine instance of
     * the audited build on real silicon" — which an attacker can also stand up
     * and proxy you to. RTMR[3] is extended after launch with the operator key
     * bound at boot (and any per-workload measurements chained onto it), so it
     * is unique to a deployment. Pinning it is what makes the verdict "this
     * operator's cluster" rather than "some genuine cluster".
     *
     * Complements `meshCaPem`, which is also cluster-unique but is regenerated
     * inside the CDS TEE on every install; the operator key survives reinstalls
     * and image rebuilds, so it can be published in advance.
     *
     * TDX only — the register does not exist on SNP, and the verifier consults
     * it only on the TDX path. Combining it with any other platform is rejected
     * rather than silently ignored.
     */
    expectedRtmr3?: string;
    /**
     * The complete TDX guest-image pin: MRTD + RTMR[1] + RTMR[2] as one tuple,
     * each exactly 96 lowercase hex chars, published with the image build (feed
     * a manifest file to {@link parseImageManifest}). `measurements` alone pins
     * only MRTD, which covers the TDVF firmware — the guest kernel and rootfs
     * land in RTMR[1]/RTMR[2], so only the tuple identifies the image. The
     * tuple's `mrtd` joins the `measurements` allowlist and `rtmr1`/`rtmr2` are
     * compared exactly against the verified claims. All three registers or
     * none: a partial tuple is rejected rather than partially enforced.
     *
     * Required for a TDX deployment-class verdict (no `meshCaPem`), where the
     * measurement policy is the entire anchor; with a pinned mesh CA it is
     * strongly recommended, and its absence is a prominent warning.
     *
     * TDX only — SNP's launch measurement already covers the full image and has
     * no runtime-register equivalent, so combining this with any other platform
     * is rejected rather than silently ignored.
     */
    tdxImage?: TdxImage;
    /**
     * Minimum SEV-SNP TCB floor, pinned from AMD security bulletins. A verified
     * report whose reported TCB is below any component fails closed
     * (`tcb_denied`). Measurement pinning does not replace this: a genuine,
     * correctly-measured guest on unpatched platform firmware verifies without
     * it. SNP platforms only ("snp" | "az-snp") — TDX has its own TCB model, so
     * the pin is rejected elsewhere rather than silently dropped.
     */
    minTcb?: SnpMinTcb;
    /**
     * DER-encoded AMD KDS CRL for the deployment's processor generation
     * (`https://kdsintf.amd.com/vcek/v1/<product>/crl`), fetched or stapled by
     * the caller — the WASM verifier cannot reach AMD KDS itself. The bytes
     * need no transport trust: the verifier checks the CRL's signature against
     * the bundled AMD root and its thisUpdate/nextUpdate freshness window
     * before trusting it, then requires the VEK to not be revoked. Supplying it
     * makes revocation part of the verdict (`collateralVerified: true`); a
     * supplied CRL that cannot be positively verified fails closed
     * (`collateral_denied`), never as "skipped". SNP platforms only.
     */
    snpCrl?: Uint8Array;
    /**
     * Require the revocation collateral to be verified for the verdict to pass
     * (production policy). With this set, a result whose collateral was never
     * checked fails with `collateral_required` instead of verifying with a
     * warning. Requires `snpCrl` — requiring collateral while supplying none
     * could never succeed and is rejected upfront. SNP platforms only: the
     * browser verifier has no TDX collateral path yet, so requiring it there
     * is rejected rather than accepted-and-always-failing.
     */
    requireCollateral?: boolean;
}
export interface AttestationBundle {
    version: string;
    platform: string;
    /**
     * SNP processor generation the responder declares. Not trusted on its own:
     * it selects the VCEK/ASK/ARK chain the report is verified against, so a
     * wrong value fails that chain — and {@link VerifyPolicy.generation} pins it
     * outright when the caller wants the mismatch stated rather than inferred.
     */
    generation: string;
    nonce: string;
    evidence: Evidence;
    cds_cert_pem: string;
    /** Credential model terminating the front door ("cds" | "webpki" | "acme"), committed by the transcript. */
    front_door_mode: string;
    ear?: string;
    /** Echo of the client's X-Wing encapsulation key (base64url, 1216 bytes). */
    xwing_ek: string;
    /** The server's X-Wing ciphertext (base64url, 1120 bytes). */
    xwing_ct: string;
    /** The session identifier (base64url, 16 bytes), committed by report_data. */
    session_id: string;
    identity_proof: MeshIdentityProof;
}
/** Claims block inside the WASM verifier's JSON result. */
export interface WasmClaims {
    launch_digest: string;
    report_data?: string;
    [key: string]: unknown;
}
/** Parsed JSON result returned by the WASM verifier. */
export interface WasmVerifyResult {
    signature_valid: boolean;
    platform: string;
    generation?: string;
    report_version?: number;
    report_data_match: boolean | null;
    collateral_verified?: boolean;
    /**
     * RTMR[3] comparison result, present only when a pin was supplied. The
     * verifier core omits the field entirely when it never performed the
     * comparison, so `undefined` means "not checked" — never "fine".
     */
    rtmr3_match?: boolean | null;
    claims: WasmClaims;
}
export interface CertInfo {
    subjectCN: string | null;
    issuerCN: string | null;
    sha256: string;
    caSha256: string;
    notAfter: string;
}
/** A verified matched-workload stamp, surfaced on the result. */
export interface WorkloadInfo {
    /** The stamped (and, when pinned, matched) workload name. */
    name: string;
    /** Allowlist store version the stamp's match was decided under. */
    allowlistVersion: string;
    /** Hex SHA-256 of the canonical allowlist bytes the stamp commits to. */
    allowlistDigestHex: string;
}
export interface AttestationResult {
    ok: true;
    platform: string;
    measurement: string;
    reportVersion: number;
    reportDataMatch: boolean | null;
    /** true only when the identity transcript is hardware-bound (report_data matched). */
    identityBound: boolean;
    /**
     * Whether endorsement/revocation collateral was verified as part of this
     * verdict (for SNP: the AMD KDS CRL's signature and freshness checked, and
     * the VEK not on it). `false` means revocation was never checked — the
     * verdict is hardware-signature- and measurement-complete but not
     * collateral-complete, and a matching warning says so. Set
     * {@link VerifyPolicy.requireCollateral} to make `false` a failure instead.
     */
    collateralVerified: boolean;
    /**
     * Verified identity transcript hash used as the HKDF salt. Hardware-bound
     * only when {@link identityBound} is true.
     */
    keyAgreementContext: Uint8Array;
    /** The decoded, echo-checked key exchange: our ek, the server's ct, the session id. */
    keyExchange: KeyExchangeEcho;
    /** The front-door credential model the endpoint committed into the verified transcript. */
    frontDoorMode: string;
    cert: CertInfo;
    claims: WasmClaims;
    /**
     * The mesh leaf's verified matched-workload stamp. Present only when a
     * workload policy (`workloadName` and/or `allowlist`) was pinned and every
     * check passed; without a pin the stamp is not read at all.
     */
    workload?: WorkloadInfo;
    /**
     * What the verdict identifies. `"specific-cluster"` iff `meshCaPem` was
     * pinned: the chain anchors to a CA the caller chose out of band.
     * `"deployment-class"` means the CA was derived from the transcript
     * commitment — the verdict says "a genuine instance of this measured
     * deployment", never "my cluster"; a genuine clone cluster booted from the
     * same measured images and policy is indistinguishable by public inputs.
     */
    trustClass: "deployment-class" | "specific-cluster";
    /**
     * The TDX runtime measurement registers this verdict compared exactly, as
     * "<index>:<expected hex>" (e.g. "1:<rtmr1>", "2:<rtmr2>" from the
     * `tdxImage` tuple, "3:<rtmr3>" from `expectedRtmr3`). Present only when at
     * least one register pin was enforced — absent means only the launch digest
     * was pinned.
     */
    rtmrsPinned?: string[];
    warnings: string[];
}
/**
 * Enforce the RTMR[1]/RTMR[2] half of a TDX image pin against the VERIFIED
 * claims (the tuple's MRTD is enforced through the launch-digest allowlist
 * instead). Register-exact lowercase-hex comparison; an absent or malformed
 * claim fails closed — a claim that cannot be compared must never read as a
 * pin that held. Returns the `rtmrsPinned` entries ("<idx>:<hex>") recorded on
 * the result. Exported for direct testing of the fail-closed paths; callers
 * go through {@link verifyAttestation} / {@link verifyEvidence}.
 */
export declare function enforceTdxImagePins(result: WasmVerifyResult, image: TdxImage): string[];
/** The decoded key-exchange half of the bundle. */
export interface KeyExchangeEcho {
    xwingEk: Uint8Array;
    xwingCt: Uint8Array;
    sessionId: Uint8Array;
}
/**
 * Verify an attestation bundle end to end.
 *
 * @param bundle the LB attest-pq response
 * @param nonce the nonce WE generated and sent
 * @param policy the verification policy
 * @param expectedXwingEk the X-Wing encapsulation key WE sent; the bundle must
 *   echo it exactly. Omit only when re-verifying a saved bundle offline, where
 *   the result is not a freshness or key-binding proof for this caller.
 */
export declare function verifyAttestation(bundle: AttestationBundle, nonce: Uint8Array, policy: VerifyPolicy, expectedXwingEk?: Uint8Array): Promise<AttestationResult>;
export interface VerifyEvidenceOptions {
    /**
     * "milan" | "genoa" | "turin"; required for "snp", ignored for "az-snp"
     * (auto-detected from CPUID) and the TDX platforms
     */
    generation?: string;
    /** accepted launch digests (hex sha-384); empty = warn only */
    measurements?: string[];
    /**
     * raw bytes the freshness anchor must equal (e.g. SHA-384(pubkey ‖ nonce));
     * when provided, a mismatch fails closed. For "snp" and "tdx" this is the
     * hardware quote's report_data; for "az-snp"/"az-tdx" it is the vTPM
     * quote's extraData.
     */
    expectedReportData?: Uint8Array;
    /**
     * default "snp"; set "az-snp"/"az-tdx" for full Azure vTPM verification, or
     * "tdx" for bare-metal Intel TDX DCAP evidence
     */
    platform?: string;
    /**
     * expected TDX RTMR[3] (96 hex chars), pinned out of band; a mismatch fails
     * closed. Where `measurements` pins the build, this pins the deployment —
     * RTMR[3] carries the operator key bound at launch, which a reproducible
     * image digest cannot. Requires `platform: "tdx"`.
     */
    expectedRtmr3?: string;
    /**
     * The complete TDX guest-image pin (mrtd + rtmr1 + rtmr2, each 96 lowercase
     * hex chars; see {@link VerifyPolicy.tdxImage} and `parseImageManifest`).
     * The tuple's `mrtd` joins the `measurements` allowlist and `rtmr1`/`rtmr2`
     * are compared exactly; a mismatch or an uncomparable claim fails closed.
     * Requires `platform: "tdx"`.
     */
    tdxImage?: TdxImage;
    /** Minimum SEV-SNP TCB floor; see {@link VerifyPolicy.minTcb}. SNP only. */
    minTcb?: SnpMinTcb;
    /**
     * DER AMD KDS CRL for the deployment's generation; see
     * {@link VerifyPolicy.snpCrl}. SNP only.
     */
    snpCrl?: Uint8Array;
    /**
     * Require the revocation collateral to be verified for the verdict to
     * pass; see {@link VerifyPolicy.requireCollateral}. Requires `snpCrl`.
     */
    requireCollateral?: boolean;
}
export interface EvidenceResult {
    ok: true;
    platform: string;
    measurement: string;
    reportVersion: number;
    reportDataMatch: boolean | null;
    /** Whether revocation collateral was verified; see {@link AttestationResult.collateralVerified}. */
    collateralVerified: boolean;
    claims: WasmClaims;
    /** Register pins this verdict compared exactly; see {@link AttestationResult.rtmrsPinned}. */
    rtmrsPinned?: string[];
    warnings: string[];
}
/**
 * Verify a bare SEV-SNP evidence object: the AMD hardware signature + VCEK chain
 * (in WASM, bundled roots), the launch-measurement allowlist, the platform, and
 * — when the caller supplies one — a `report_data` binding.
 *
 * Unlike {@link verifyAttestation}, this takes the raw `attestation-rs`
 * `SnpEvidence` directly and needs no `attest-pq` bundle, client nonce,
 * session key, or CDS certificate. Use it when you fetch evidence over your own
 * transport and compute the `report_data` binding yourself (e.g. a discovery
 * document binding `SHA-384(cert_spki ‖ challenge)`). Cluster identity
 * (mesh-CA chaining) must then be checked separately. Fails closed with a typed
 * {@link C8sVerifyError}.
 */
export declare function verifyEvidence(evidence: Evidence, opts: VerifyEvidenceOptions): Promise<EvidenceResult>;
//# sourceMappingURL=verify.d.ts.map