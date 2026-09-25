// The over-encryption record layer: AES-256-GCM with one key and IV prefix per
// direction, deterministic counter nonces, and AADs framing the direction,
// session id, and sequence number. A response must echo its request's
// sequence, so the untrusted TLS terminator can neither replay a record nor
// cross the responses of two concurrent requests. Must match Go pkg/overenc.
import { subtle } from "./crypto-env.js";
import { utf8ToBytes, concatBytes } from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";
/** Session identifier length; the transcript and every record AAD frame it. */
export const SESSION_ID_BYTES = 16;
/** Channel-binding exporter length. */
export const EXPORTER_BYTES = 32;
const SEQ_BYTES = 8;
// How far behind the highest accepted sequence a reordered request may arrive
// (server role). Matches Go overenc.replayWindow.
const REPLAY_WINDOW = 64;
// The method and path are sealed inside the request envelope, so the AAD tags
// are per-direction domain separators rather than per-route.
const REQUEST_AAD_TAG = utf8ToBytes("c8s-verify/v1/tunnel-request");
const RESPONSE_AAD_TAG = utf8ToBytes("c8s-verify/v1/tunnel-response");
function seqBytes(seq) {
    if (!Number.isSafeInteger(seq) || seq < 0) {
        fail("channel_error", `record sequence ${seq} is not a safe non-negative integer`);
    }
    const out = new Uint8Array(SEQ_BYTES);
    new DataView(out.buffer).setBigUint64(0, BigInt(seq), false);
    return out;
}
/**
 * One end of the over-encryption channel. The client end seals requests and
 * opens responses; the server end (mock LB, tests) opens requests and seals
 * responses.
 */
export class Channel {
    send;
    recv;
    sessionId;
    /**
     * Channel-binding exporter: both ends derive it from the shared secret under
     * the identity transcript; it is never sent on the wire. Bind bearer
     * credentials to it so a token exfiltrated from one channel is useless on
     * any other. The sidecar forwards it to the backend as X-C8s-Exporter.
     */
    exporter;
    nextSeq = 1;
    seqHigh = 0;
    seqSeen = new Set();
    constructor(send, recv, sessionId, exporter) {
        if (sessionId.length !== SESSION_ID_BYTES) {
            fail("channel_error", `session id must be ${SESSION_ID_BYTES} bytes, got ${sessionId.length}`);
        }
        this.send = send;
        this.recv = recv;
        this.sessionId = sessionId;
        this.exporter = exporter;
    }
    aad(tag, seq) {
        return concatBytes(tag, this.sessionId, seqBytes(seq));
    }
    nonce(ivPrefix, seq) {
        return concatBytes(ivPrefix, seqBytes(seq));
    }
    async sealWith(plaintext, seq) {
        if (seq === 0)
            fail("channel_error", "record sequence 0 is invalid");
        const ct = await subtle().encrypt({
            name: "AES-GCM",
            iv: this.nonce(this.send.ivPrefix, seq),
            additionalData: this.aad(this.send.aadTag, seq),
        }, this.send.key, plaintext);
        return { seq, ct: new Uint8Array(ct) };
    }
    async openWith(record) {
        const seq = record?.seq;
        const ct = record?.ct;
        if (typeof seq !== "number" || !(ct instanceof Uint8Array)) {
            fail("channel_error", "malformed over-encryption record");
        }
        if (!Number.isSafeInteger(seq) || seq <= 0) {
            fail("channel_error", "record sequence must be a positive integer");
        }
        try {
            const pt = await subtle().decrypt({
                name: "AES-GCM",
                iv: this.nonce(this.recv.ivPrefix, seq),
                additionalData: this.aad(this.recv.aadTag, seq),
            }, this.recv.key, ct);
            return new Uint8Array(pt);
        }
        catch (e) {
            throw new C8sVerifyError("channel_error", "over-encryption record failed authentication (AES-GCM)", { cause: e });
        }
    }
    /** Seal a request under this end's next sequence number (client role). */
    async sealRequest(plaintext) {
        return this.sealWith(plaintext, this.nextSeq++);
    }
    /**
     * Open a response record (client role). It must echo the sequence of the
     * request it answers — what stops the terminator crossing the responses of
     * two concurrent requests.
     */
    async openResponse(record, requestSeq) {
        if (record?.seq !== requestSeq) {
            fail("channel_error", `response sequence ${record?.seq} does not echo request sequence ${requestSeq}`);
        }
        return this.openWith(record);
    }
    /**
     * Open a request record (server role), enforcing the sliding replay window:
     * a replayed record, or one reordered further than the window behind the
     * newest accepted request, is rejected. Only authenticated records advance
     * the window.
     */
    async openRequest(record) {
        const pt = await this.openWith(record);
        this.acceptSeq(record.seq);
        return pt;
    }
    /** Seal a response echoing the request's sequence (server role). */
    async sealResponse(plaintext, requestSeq) {
        return this.sealWith(plaintext, requestSeq);
    }
    acceptSeq(seq) {
        if (seq > this.seqHigh) {
            this.seqHigh = seq;
        }
        else if (this.seqHigh - seq >= REPLAY_WINDOW || this.seqSeen.has(seq)) {
            fail("channel_error", "replayed or out-of-window record rejected");
        }
        this.seqSeen.add(seq);
        for (const old of this.seqSeen) {
            if (this.seqHigh - old >= REPLAY_WINDOW)
                this.seqSeen.delete(old);
        }
    }
}
/** Assemble a Channel end for the given role from the derived key schedule. */
export function newChannel(role, keys, sessionId) {
    const c2s = { key: keys.c2sKey, ivPrefix: keys.c2sIv, aadTag: REQUEST_AAD_TAG };
    const s2c = { key: keys.s2cKey, ivPrefix: keys.s2cIv, aadTag: RESPONSE_AAD_TAG };
    return role === "client"
        ? new Channel(c2s, s2c, sessionId, keys.exporter)
        : new Channel(s2c, c2s, sessionId, keys.exporter);
}
//# sourceMappingURL=channel.js.map