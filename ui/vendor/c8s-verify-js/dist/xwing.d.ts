export declare const XWING_EK_BYTES: number;
export declare const XWING_CT_BYTES: number;
export declare const XWING_SS_BYTES = 32;
export declare const XWING_SEED_BYTES = 32;
/** An X-Wing decapsulation keypair: component private handles plus the wire ek. */
export interface XWingKeyPair {
    /** 1216-byte encapsulation key sent in the attestation request. */
    ek: Uint8Array;
    mlkemPriv: CryptoKey;
    x25519Priv: CryptoKey;
}
/** Generate a fresh X-Wing keypair from system randomness. */
export declare function generateXWingKeyPair(): Promise<XWingKeyPair>;
/**
 * Rebuild an X-Wing keypair from its 32-byte seed (draft §5.2: the seed
 * expands via SHAKE-256 to the ML-KEM d||z coins and the X25519 scalar). Used
 * by the interoperability vectors; sessions use {@link generateXWingKeyPair}.
 */
export declare function xwingKeyPairFromSeed(seed: Uint8Array): Promise<XWingKeyPair>;
/**
 * Decapsulate the server's ciphertext to the 32-byte shared secret. An
 * ML-KEM-invalid ciphertext yields the implicit-rejection secret rather than
 * an error, so a tampered exchange surfaces as an AEAD failure on the first
 * record — never as a decapsulation oracle.
 */
export declare function xwingDecapsulate(kp: XWingKeyPair, ct: Uint8Array): Promise<Uint8Array>;
/**
 * Encapsulate to an X-Wing encapsulation key. The server side of the exchange;
 * in this library it serves the mock LB and tests.
 */
export declare function xwingEncapsulate(ek: Uint8Array): Promise<{
    ct: Uint8Array;
    sharedSecret: Uint8Array;
}>;
//# sourceMappingURL=xwing.d.ts.map