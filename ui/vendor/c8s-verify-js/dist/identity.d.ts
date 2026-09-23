import { type Certificate } from "./x509.js";
import type { PublicHalves } from "./keyagreement.js";
/**
 * Binding identifier of the `attest-pq` response bundle. Each endpoint's
 * response carries its own identifier and a client requires the one selected
 * by its endpoint — `c8s/attest-lb/v1` (a native-client sibling protocol this
 * browser library cannot implement) and the retired `c8s-verify/v1` bundle
 * are rejected even when their evidence is otherwise valid.
 */
export declare const BINDING_ATTEST_PQ = "c8s/attest-pq/v1";
/**
 * Identity-transcript domain tag, shared with c8s pkg/overenc. Deliberately
 * NOT the bundle binding id above: the transcript construction (and the HKDF
 * info derived from it) is unchanged from the original protocol, only the
 * endpoint and its bundle version moved.
 */
export declare const TRANSCRIPT_DOMAIN_TAG = "c8s-verify/v1";
export declare const IDENTITY_PROOF_ALGORITHM = "ecdsa-sha384";
/** SHA-384 transcript hash length; also the v1 HKDF context length. */
export declare const IDENTITY_TRANSCRIPT_BYTES = 48;
export interface MeshIdentityProof {
    algorithm: string;
    leaf_sha256: string;
    mesh_ca_sha256: string;
    signature: string;
}
/**
 * Compute the v1 report_data transcript shared with c8s/pkg/overenc.
 */
export declare function identityTranscriptHash(pub: PublicHalves, nonce: Uint8Array, leafDer: Uint8Array, caDer: Uint8Array, mode?: string): Promise<Uint8Array>;
/** Reject anything that is not a SHA-384 transcript hash. */
export declare function assertTranscriptLength(transcriptHash: Uint8Array): void;
/**
 * Select the pinned CA the proof commits to, comparing decoded hash bytes so
 * selection accepts exactly the encodings {@link verifyMeshIdentityProof}
 * accepts. Returns undefined when the proof names none of the pinned CAs.
 */
export declare function selectPinnedCA(proof: MeshIdentityProof, pinnedCADers: Uint8Array[]): Promise<Uint8Array | undefined>;
/** Verify certificate fingerprints and proof of possession for a v1 transcript. */
export declare function verifyMeshIdentityProof(proof: MeshIdentityProof, transcriptHash: Uint8Array, leaf: Certificate, ca: Certificate): Promise<void>;
export declare function certificateHashBase64Url(der: Uint8Array): Promise<string>;
//# sourceMappingURL=identity.d.ts.map