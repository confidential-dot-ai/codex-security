/**
 * Clock-skew allowance granted to NotBefore, mirroring c8s's
 * `certutil.LeafValiditySkew`. CDS mints mesh leaves with `NotBefore: now` and
 * no backdating, and re-reads them per request so a rotation is picked up
 * mid-flight — so a browser whose clock trails the issuing TEE by a moment
 * would otherwise reject a perfectly fresh leaf. NotAfter gets NO allowance:
 * an expired certificate is expired, and these bundles carry no nonce of their
 * own, so the validity window is the only bound on replaying one.
 */
export declare const LEAF_VALIDITY_SKEW_MS: number;
export interface Certificate {
    der: Uint8Array;
    tbs: Uint8Array;
    serialHex: string;
    notBefore: Date;
    notAfter: Date;
    subjectCN: string | null;
    issuerCN: string | null;
    /**
     * Verbatim DER of the issuer and subject Name elements. Chaining compares
     * these bytes, not the decoded CNs: a Name is a structure, and two different
     * structures can share a CN (or carry none at all, as the c8s mesh leaf
     * does), so anything short of byte equality lets a leaf claim an issuer it
     * does not have.
     */
    rawIssuer: Uint8Array;
    rawSubject: Uint8Array;
    spki: Uint8Array;
    spkiCurve: string | null;
    sigAlgOID: string;
    signatureDER: Uint8Array;
    /**
     * Extension values by OID, as the raw extnValue OCTET STRING contents.
     *
     * Kept raw and unparsed on purpose: what a verifier enforces has to be the
     * exact bytes the issuer signed — the matched-workload stamp is decoded from
     * this DER verbatim, and the RA-TLS attestation extension is the value the
     * quote's REPORTDATA commits to. Anything that re-encodes before comparing or
     * hashing would compute a different value for the same certificate.
     */
    extensions: Map<string, Uint8Array>;
}
export interface ChainResult {
    leaf: Certificate;
    ca: Certificate;
    leafSha256: string;
    caSha256: string;
}
/**
 * Parse a DER-encoded X.509 certificate.
 */
export declare function parseCertificate(der: Uint8Array): Certificate;
/** Verify an ASN.1 DER ECDSA signature with a certificate public key. */
export declare function verifyECDSASignature(cert: Certificate, message: Uint8Array, signatureDER: Uint8Array, hash: "SHA-256" | "SHA-384"): Promise<boolean>;
/**
 * Import a certificate's SubjectPublicKeyInfo as an ECDSA verify key.
 */
export declare function importPublicKey(cert: Certificate): Promise<CryptoKey>;
/**
 * SHA-256 fingerprint of a certificate (DER), as lowercase hex.
 */
export declare function fingerprintSHA256(cert: Certificate | Uint8Array): Promise<string>;
/**
 * Verify that `child` was signed by `issuer` (ECDSA), that `issuer` is a
 * certificate allowed to have signed it, and that both are within their
 * validity windows at `at`. Throws C8sVerifyError on any failure.
 *
 * A valid signature alone is not a chain. The responder chooses every byte of
 * the served certificate bundle, so without the issuer checks below "signed
 * by" degenerates to "some certificate signed this one": emitting one
 * self-signed certificate twice makes the leaf its own CA, and everything the
 * chain is meant to vouch for — the matched-workload stamp above all — becomes
 * attacker-chosen. Go's `CheckSignatureFrom` enforces the constraint half of
 * this and `Verify` the name half, which is why the c8s server has no such
 * hole; the rules are restated here rather than inherited.
 */
export declare function verifySignedBy(child: Certificate, issuer: Certificate, opts?: {
    at?: Date;
}): Promise<void>;
/**
 * Parse a leaf + CA from DER and verify the chain link.
 */
export declare function verifyCertChain(leafDer: Uint8Array, caDer: Uint8Array, opts?: {
    at?: Date;
}): Promise<ChainResult>;
//# sourceMappingURL=x509.d.ts.map