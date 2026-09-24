import { type Channel, type ChannelRole } from "./channel.js";
export { XWING_EK_BYTES, XWING_CT_BYTES, XWING_SS_BYTES, generateXWingKeyPair, xwingKeyPairFromSeed, xwingDecapsulate, xwingEncapsulate, } from "./xwing.js";
export type { XWingKeyPair } from "./xwing.js";
/**
 * Derive the full channel key schedule and assemble this end's Channel.
 *
 * @param role which end this is: the browser client, or the server half used
 *   by the mock LB and tests
 * @param sharedSecret 32-byte X-Wing shared secret
 * @param identityTranscript verified 48-byte identity transcript hash (salt)
 * @param sessionId 16-byte session id, committed by the transcript
 */
export declare function deriveChannel(role: ChannelRole, sharedSecret: Uint8Array, identityTranscript: Uint8Array, sessionId: Uint8Array): Promise<Channel>;
/**
 * Derive the raw key-schedule outputs without importing them into AEAD
 * handles. For the interoperability-vector tests, which compare the bytes.
 */
export declare function deriveRawKeySchedule(sharedSecret: Uint8Array, identityTranscript: Uint8Array): Promise<{
    c2sKey: Uint8Array;
    s2cKey: Uint8Array;
    c2sIv: Uint8Array;
    s2cIv: Uint8Array;
    exporter: Uint8Array;
}>;
//# sourceMappingURL=keyagreement.d.ts.map