/** Session identifier length; the transcript and every record AAD frame it. */
export declare const SESSION_ID_BYTES = 16;
/** Channel-binding exporter length. */
export declare const EXPORTER_BYTES = 32;
/**
 * Raw record; the tunnel transport carries it as a CBOR map with an unsigned
 * `seq` and a byte-string `ct`.
 */
export interface WireRecord {
    seq: number;
    ct: Uint8Array;
}
/** One direction's sealing or opening half. */
interface DirectionKeys {
    key: CryptoKey;
    ivPrefix: Uint8Array;
    aadTag: Uint8Array;
}
/**
 * One end of the over-encryption channel. The client end seals requests and
 * opens responses; the server end (mock LB, tests) opens requests and seals
 * responses.
 */
export declare class Channel {
    private readonly send;
    private readonly recv;
    private readonly sessionId;
    /**
     * Channel-binding exporter: both ends derive it from the shared secret under
     * the identity transcript; it is never sent on the wire. Bind bearer
     * credentials to it so a token exfiltrated from one channel is useless on
     * any other. The sidecar forwards it to the backend as X-C8s-Exporter.
     */
    readonly exporter: Uint8Array;
    private nextSeq;
    private seqHigh;
    private seqSeen;
    constructor(send: DirectionKeys, recv: DirectionKeys, sessionId: Uint8Array, exporter: Uint8Array);
    private aad;
    private nonce;
    private sealWith;
    private openWith;
    /** Seal a request under this end's next sequence number (client role). */
    sealRequest(plaintext: Uint8Array): Promise<WireRecord>;
    /**
     * Open a response record (client role). It must echo the sequence of the
     * request it answers — what stops the terminator crossing the responses of
     * two concurrent requests.
     */
    openResponse(record: WireRecord, requestSeq: number): Promise<Uint8Array>;
    /**
     * Open a request record (server role), enforcing the sliding replay window:
     * a replayed record, or one reordered further than the window behind the
     * newest accepted request, is rejected. Only authenticated records advance
     * the window.
     */
    openRequest(record: WireRecord): Promise<Uint8Array>;
    /** Seal a response echoing the request's sequence (server role). */
    sealResponse(plaintext: Uint8Array, requestSeq: number): Promise<WireRecord>;
    private acceptSeq;
}
export type ChannelRole = "client" | "server";
/** Inputs a role's Channel is assembled from; produced by the key schedule. */
export interface ChannelKeys {
    c2sKey: CryptoKey;
    s2cKey: CryptoKey;
    c2sIv: Uint8Array;
    s2cIv: Uint8Array;
    exporter: Uint8Array;
}
/** Assemble a Channel end for the given role from the derived key schedule. */
export declare function newChannel(role: ChannelRole, keys: ChannelKeys, sessionId: Uint8Array): Channel;
export {};
//# sourceMappingURL=channel.d.ts.map