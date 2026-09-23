// c8s-verify: public API.
//
// Verify that a remote API is served by a genuine, TEE-attested, CDS-issued C8s
// Load Balancer, then talk to it over a post-quantum over-encrypted channel that
// terminates inside the LB's enclave — so a malicious TLS-terminating proxy in
// front of the LB cannot read or forge application traffic.
//
//   const client = new C8sClient({ baseUrl, measurements: [...], meshCaPem });
//   const session = await client.connect();
//   console.log(session.attestation.measurement);
//   const res = await session.fetch("/v1/chat", { method: "POST", body: "..." });
import { generateNonce } from "./nonce.js";
import { verifyAttestation, } from "./verify.js";
import { deriveChannel, generateXWingKeyPair, xwingDecapsulate, } from "./keyagreement.js";
import { cborEncode, cborDecode } from "./cbor.js";
import { bytesToBase64Url, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";
export { C8sVerifyError } from "./errors.js";
export { BINDING_ATTEST_PQ, TRANSCRIPT_DOMAIN_TAG } from "./identity.js";
export { verifyAttestation, verifyEvidence } from "./verify.js";
// The matched-workload stamp: parse the mesh leaf's .1.5 extension and the
// allowlist document it pins. verifyAttestation applies these automatically
// when the policy pins workloadName/allowlist; they are exported for callers
// that verify certificates through their own transport.
export { OID_MATCHED_WORKLOAD, parseMatchedWorkload, parseAllowlist, resolveWorkload, allowlistDigestHex, } from "./workload.js";
// The TDX image pin: parse a published build-artifact manifest into the
// mrtd+rtmr1+rtmr2 tuple `tdxImage` enforces.
export { parseImageManifest } from "./manifest.js";
export { decodePEM, decodeOnePEM, encodePEM } from "./pem.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
const WELL_KNOWN = "/.well-known/c8s";
export class C8sClient {
    baseUrl;
    prefix;
    fetch;
    /** Verification policy applied to every connection. */
    policy;
    constructor(opts) {
        if (!opts?.baseUrl) {
            throw new C8sVerifyError("invalid_request", "baseUrl is required");
        }
        // At least one anchor: a pinned mesh CA (specific-cluster), pinned
        // canonical allowlist bytes enforced against the workload stamp
        // (deployment-class), or both. verifyAttestation re-validates the shapes;
        // refusing an anchorless client here means the misconfiguration surfaces
        // at construction, not at the first connection.
        const hasPem = typeof opts.meshCaPem === "string" && opts.meshCaPem.trim() !== "";
        const hasAllowlist = opts.allowlist !== undefined && opts.allowlist.length > 0;
        if (!hasPem && !hasAllowlist) {
            throw new C8sVerifyError("invalid_request", "verification requires an anchor: pass meshCaPem to pin the mesh CA out of band " +
                "(specific-cluster), or allowlist with the exact canonical allowlist bytes to enforce " +
                "against the mesh leaf's matched-workload stamp (deployment-class), or both");
        }
        this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
        this.prefix = opts.wellKnownPrefix ?? WELL_KNOWN;
        const f = opts.fetch ?? globalThis.fetch?.bind(globalThis);
        if (!f) {
            throw new C8sVerifyError("invalid_request", "no fetch implementation available");
        }
        this.fetch = f;
        this.policy = {
            measurements: opts.measurements,
            platform: opts.platform,
            generation: opts.generation,
            requireFreshness: opts.requireFreshness,
            meshCaPem: hasPem ? opts.meshCaPem : undefined,
            allowlist: opts.allowlist,
            workloadName: opts.workloadName,
            at: opts.at,
            expectedRtmr3: opts.expectedRtmr3,
            tdxImage: opts.tdxImage,
            minTcb: opts.minTcb,
            snpCrl: opts.snpCrl,
            requireCollateral: opts.requireCollateral,
        };
    }
    _url(path) {
        return `${this.baseUrl}${path}`;
    }
    /**
     * POST the client-first attest-pq request — the fresh nonce and our X-Wing
     * encapsulation key — and return the bundle. There is no fallback, alias,
     * or version parameter: the endpoint is the version selector, and a server
     * that does not serve it is a server this client cannot verify.
     */
    async fetchAttestation(nonce, keyPair) {
        const res = await this.fetch(`${this._url(this.prefix)}/attest-pq`, {
            method: "POST",
            headers: { "content-type": "application/json", accept: "application/json" },
            body: JSON.stringify({
                nonce: bytesToBase64Url(nonce),
                xwing_ek: bytesToBase64Url(keyPair.ek),
            }),
        });
        if (!res.ok) {
            fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
        }
        return (await res.json());
    }
    /**
     * Run the full flow in one round trip: send our key exchange, verify the
     * returned evidence (which commits both sides of it), decapsulate, and
     * derive the over-encrypted channel. The session is live on return.
     */
    async connect() {
        const nonce = generateNonce();
        const keyPair = await generateXWingKeyPair();
        const bundle = await this.fetchAttestation(nonce, keyPair);
        const attestation = await verifyAttestation(bundle, nonce, this.policy, keyPair.ek);
        const sharedSecret = await xwingDecapsulate(keyPair, attestation.keyExchange.xwingCt);
        const channel = await deriveChannel("client", sharedSecret, attestation.keyAgreementContext, attestation.keyExchange.sessionId);
        return new Session({
            baseUrl: this.baseUrl,
            prefix: this.prefix,
            fetch: this.fetch,
            channel,
            sessionId: bundle.session_id,
            attestation,
        });
    }
}
/**
 * An established, verified, over-encrypted session with the LB.
 */
export class Session {
    baseUrl;
    prefix;
    _fetch;
    channel;
    sessionId;
    /** Verification result: measurement, platform, cert info, warnings, ... */
    attestation;
    constructor(o) {
        this.baseUrl = o.baseUrl;
        this.prefix = o.prefix;
        this._fetch = o.fetch;
        this.channel = o.channel;
        this.sessionId = o.sessionId;
        this.attestation = o.attestation;
    }
    /**
     * Channel-binding exporter (32 bytes): derived by both ends from the shared
     * secret under the attested transcript, never sent on the wire. The sidecar
     * hands the backend the same value as the X-C8s-Exporter header, so an
     * application can bind bearer credentials to this exact channel.
     */
    get exporter() {
        return this.channel.exporter;
    }
    /**
     * Make an over-encrypted request to the LB. The entire request — method, path,
     * headers, and body — is sealed with AES-256-GCM and sent to the tunnel
     * endpoint, so a TLS-terminating proxy in front of the LB sees only ciphertext.
     * The LB enclave decrypts it, forwards the plaintext request to the backend
     * (over the cluster raTLS mesh), and seals the response back.
     */
    async fetch(path, init = {}) {
        const method = (init.method ?? "GET").toUpperCase();
        const bodyBytes = init.body === undefined
            ? new Uint8Array(0)
            : typeof init.body === "string"
                ? utf8ToBytes(init.body)
                : init.body;
        const headerPairs = Array.isArray(init.headers)
            ? init.headers
            : Object.entries(init.headers ?? {});
        const envelope = {
            method,
            path,
            headers: headerPairs,
            body: bodyBytes,
        };
        const reqRecord = await this.channel.sealRequest(cborEncode(envelope));
        const res = await this._fetch(`${this.baseUrl}${this.prefix}/tunnel`, {
            method: "POST",
            headers: { "content-type": "application/cbor", "x-c8s-session": this.sessionId },
            body: cborEncode({ seq: reqRecord.seq, ct: reqRecord.ct }),
        });
        if (!res.ok) {
            fail("channel_error", `over-encrypted request returned HTTP ${res.status}`);
        }
        const respRecord = cborDecode(new Uint8Array(await res.arrayBuffer()));
        const respEnvelope = cborDecode(await this.channel.openResponse(respRecord, reqRecord.seq));
        const headersList = responseHeaderPairs(respEnvelope.headers);
        const bytes = respEnvelope.body ?? new Uint8Array(0);
        return {
            status: respEnvelope.status,
            headers: firstValues(headersList),
            headersList,
            bytes,
            text: () => bytesToUtf8(bytes),
        };
    }
}
/** First value of each field, for the collapsed record view. */
function firstValues(pairs) {
    const out = {};
    for (const [name, value] of pairs) {
        if (!(name in out))
            out[name] = value;
    }
    return out;
}
/** Validate a response envelope's header pair list, refusing anything else. */
function responseHeaderPairs(headers) {
    if (headers === undefined || headers === null)
        return [];
    if (!Array.isArray(headers)) {
        fail("channel_error", "malformed headers in response envelope");
    }
    for (const pair of headers) {
        if (!Array.isArray(pair) ||
            pair.length !== 2 ||
            typeof pair[0] !== "string" ||
            typeof pair[1] !== "string") {
            fail("channel_error", "malformed header pair in response envelope");
        }
    }
    return headers;
}
//# sourceMappingURL=index.js.map