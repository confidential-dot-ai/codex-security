/**
 * Raw AES-GCM record; the tunnel transport carries iv/ct as CBOR byte strings.
 */
export interface WireRecord {
    iv: Uint8Array;
    ct: Uint8Array;
}
/** AAD for a request record. */
export declare function requestAAD(): Uint8Array;
/** AAD for a response record. */
export declare function responseAAD(): Uint8Array;
/**
 * A symmetric over-encryption channel. Both client and LB hold one after the
 * hybrid handshake; the AES key is identical on both ends.
 */
export declare class Channel {
    readonly key: CryptoKey;
    /** @param key AES-256-GCM key */
    constructor(key: CryptoKey);
    /**
     * Encrypt a plaintext record.
     */
    seal(plaintext: Uint8Array, aad: Uint8Array): Promise<WireRecord>;
    /**
     * Decrypt a record. Throws channel_error on authentication failure.
     */
    open(record: WireRecord, aad: Uint8Array): Promise<Uint8Array>;
    /** Convenience: seal a UTF-8 string. */
    sealText(text: string, aad: Uint8Array): Promise<WireRecord>;
    /** Convenience: open to a UTF-8 string. */
    openText(record: WireRecord, aad: Uint8Array): Promise<string>;
}
//# sourceMappingURL=channel.d.ts.map