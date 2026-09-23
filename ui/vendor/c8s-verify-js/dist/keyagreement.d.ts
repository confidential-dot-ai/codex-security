export declare const MLKEM768_EK_BYTES = 1184;
export declare const MLKEM768_CT_BYTES = 1088;
export declare const X25519_PUB_BYTES = 32;
/** Raw public halves of the LB's hybrid key. */
export interface PublicHalves {
    x25519: Uint8Array;
    mlkem768: Uint8Array;
}
/** The client's contribution sent to the LB to complete the handshake. */
export interface Handshake {
    clientX25519: Uint8Array;
    mlkemCiphertext: Uint8Array;
}
/** Server-side (LB) private key handles. */
export interface ServerKeys {
    x25519Priv: CryptoKey;
    mlkemPriv: CryptoKey;
}
/**
 * Client side: encapsulate against the LB's attested hybrid public key and derive
 * the session key.
 *
 * @param peerPub raw public halves
 * @param identityTranscript verified identity transcript hash
 */
export declare function clientKeyAgreement(peerPub: PublicHalves, identityTranscript: Uint8Array): Promise<{
    key: CryptoKey;
    handshake: Handshake;
}>;
/**
 * LB / server side: decapsulate the client's ciphertext and ECDH against the
 * client's X25519 public key to derive the same session key. Used by the mock LB
 * and by tests.
 */
export declare function serverKeyAgreement(serverKeys: ServerKeys, handshake: Handshake, identityTranscript: Uint8Array): Promise<CryptoKey>;
/**
 * Generate a fresh LB-side hybrid keypair and return both the private handles and
 * the raw public halves to publish. Used by the mock LB.
 */
export declare function generateServerHybridKey(): Promise<{
    priv: ServerKeys;
    pub: PublicHalves;
}>;
//# sourceMappingURL=keyagreement.d.ts.map