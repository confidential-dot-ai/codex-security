/** Matched-workload extension OID (c8s pkg/ratls, the 1.3.6.1.4.1.66378 arc). */
export declare const OID_MATCHED_WORKLOAD = "1.3.6.1.4.1.66378.1.5";
/**
 * A parsed matched-workload stamp: the allowlist entry a leaf's attested
 * container set uniquely matched at issuance, and the exact policy snapshot
 * the match was decided under.
 */
export interface MatchedWorkload {
    /** The matched entry name (workload-name grammar, at most 63 bytes). */
    name: string;
    /**
     * The allowlist store's monotonic version counter at the snapshot the match
     * used — a canonical positive decimal integer.
     */
    allowlistVersion: string;
    /** SHA-256 of Allowlist.Canonical() of that snapshot, exactly 32 bytes. */
    allowlistDigest: Uint8Array;
}
/**
 * Decode a DER-encoded matched-workload extension value:
 *
 *   MatchedWorkload ::= SEQUENCE {
 *       formatVersion    INTEGER,           -- exactly 1
 *       name             IA5String,         -- 1..63 bytes, workload-name grammar
 *       allowlistVersion IA5String,         -- 1..20 decimal digits, no leading zero
 *       allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical())
 *   }
 *
 * Requires the one canonical encoding: minimal DER throughout, no trailing
 * bytes or fields — no two distinct extension values may parse to the same
 * MatchedWorkload, because the CA signature (and, on the LB leaf, the
 * identity transcript) vouches for the bytes rather than their meaning.
 * Everything else fails closed with `workload_invalid`.
 */
export declare function parseMatchedWorkload(extnValue: Uint8Array): MatchedWorkload;
/** One workload entry of an allowlist document. Kept structurally loose: the
 * verifier resolves names, it does not enforce container policy. */
export interface AllowlistWorkload {
    label?: string;
    [key: string]: unknown;
}
/** The `c8s.allowlist/v1` document (the shape `GET /allowlist` serves). */
export interface AllowlistDocument {
    schema: "c8s.allowlist/v1";
    /** Admitted image digests: `sha256:<64-hex>` → image reference. */
    digests: Record<string, string>;
    /** Named workload entries; stamp names resolve as key lookups here. */
    workloads: Record<string, AllowlistWorkload>;
}
/**
 * Parse allowlist document bytes and check the schema. Parsing is for name
 * resolution only — the digest check hashes the exact bytes supplied (see
 * {@link allowlistDigestHex}), never a re-serialized copy.
 */
export declare function parseAllowlist(bytes: Uint8Array | string): AllowlistDocument;
/**
 * Resolve a stamped workload name in a pinned allowlist document — a key
 * lookup in `workloads`, failing closed when absent. An unresolved name means
 * CDS matched against a policy revision this document does not carry, which
 * the digest check normally catches first; reaching this failure indicates a
 * document that hashes right but omits the entry, and must never pass.
 */
export declare function resolveWorkload(doc: AllowlistDocument, name: string): AllowlistWorkload;
/**
 * SHA-256 over the EXACT bytes supplied, as lowercase hex.
 *
 * Canonical bytes only: the stamp commits SHA-256 over Allowlist.Canonical(),
 * so the caller must supply those bytes verbatim (the server emits canonical
 * bytes on `GET /allowlist`). Nothing here parses or re-serializes — a
 * re-encoded copy of semantically identical content is a different digest.
 */
export declare function allowlistDigestHex(bytes: Uint8Array | string): Promise<string>;
//# sourceMappingURL=workload.d.ts.map