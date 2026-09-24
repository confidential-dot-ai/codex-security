/* @ts-self-types="./attestation_wasm.d.ts" */

/**
 * Verify attestation evidence from a self-describing envelope — the generic,
 * platform-dispatching entry point and the preferred API for JS embedders.
 *
 * `envelope_json` is the core [`attestation::AttestationEvidence`] envelope:
 * `{ "platform": "<tag>", "evidence": { ... } }`, where `platform` is one of
 * the compiled-in platform tags (`snp`, `tdx`, `az-snp`, `az-tdx`, `gcp-snp`,
 * `gcp-tdx` with default features) and `evidence` is that platform's evidence
 * payload, verbatim. Dispatch happens in the Rust core
 * (`Verifier::verify_platform`), so JS callers need no per-platform routing —
 * but they MUST assert the platform themselves by comparing the result's
 * `platform` field against the one they expect, never trusting a
 * server-chosen tag to pick the verification path.
 *
 * Runs in offline mode ([`attestation::Verifier::offline`]): quote signatures
 * and cert chains verify against the bundled AMD/Intel roots (SNP evidence
 * must carry its VEK inline, as c8s evidence does), and the SNP processor
 * generation is auto-detected from the report's CPUID fields (v3+ reports).
 * Debug guests are always rejected (`allow_debug` is never exposed to the
 * browser; fail closed).
 *
 * Collateral: the TDX network-backed checks (PCK CRL, TCB status, QE
 * identity) need an async provider and are skipped. For SNP, the caller may
 * staple the AMD KDS CRL as `snp_crl_der` — its signature is verified against
 * the bundled ARK and its thisUpdate/nextUpdate window against the current
 * time before it is trusted, then the VEK is checked against it and
 * `collateral_verified` becomes `true`. Without it, revocation is skipped and
 * `collateral_verified` stays `false` — the caller's policy layer decides
 * whether that qualifies as verified.
 *
 * `min_tcb_json`, when supplied, is the minimum SNP TCB policy as
 * [`SnpTcb`] JSON (`{ "bootloader": u8, "tee": u8, "snp": u8,
 * "microcode": u8, "fmc"?: u8 }`); a report whose reported TCB is below any
 * component fails closed. SNP platforms only — it is ignored by the TDX
 * verifiers, so TDX callers must not rely on it.
 *
 * The freshness semantics of `expected_report_data` are per-platform, handled
 * inside each core verifier: for bare-metal platforms it is checked against
 * the hardware quote's `report_data` (zero-padded, constant-time); for the
 * Azure vTPM platforms it is checked against the vTPM quote's `extraData`.
 * Either way a supplied-but-mismatched anchor fails closed.
 *
 * - `envelope_json`: `{ platform, evidence }` envelope JSON
 * - `expected_report_data`: optional freshness anchor bytes
 * - `expected_init_data_hash`: optional init-data binding (SNP HOST_DATA /
 *   TDX MRCONFIGID / vTPM PCR[8])
 * - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
 * - `snp_crl_der`: optional DER AMD KDS CRL for the report's generation
 *
 * Returns the [`attestation::types::VerificationResult`] as JSON, or throws
 * on any check failure.
 * @param {string} envelope_json
 * @param {Uint8Array | null} [expected_report_data]
 * @param {Uint8Array | null} [expected_init_data_hash]
 * @param {string | null} [min_tcb_json]
 * @param {Uint8Array | null} [snp_crl_der]
 * @returns {Promise<string>}
 */
export function verify(envelope_json, expected_report_data, expected_init_data_hash, min_tcb_json, snp_crl_der) {
    const ptr0 = passStringToWasm0(envelope_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(expected_report_data) ? 0 : passArray8ToWasm0(expected_report_data, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(expected_init_data_hash) ? 0 : passArray8ToWasm0(expected_init_data_hash, wasm.__wbindgen_malloc);
    var len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(min_tcb_json) ? 0 : passStringToWasm0(min_tcb_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(snp_crl_der) ? 0 : passArray8ToWasm0(snp_crl_der, wasm.__wbindgen_malloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret;
}

/**
 * Verify Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
 *
 * Unlike [`verify_snp`], which only checks the bare SNP hardware report, this
 * verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
 * vTPM quote that binds freshness. The freshness anchor for az-snp lives in
 * the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
 * — the SNP `report_data` instead binds the vTPM attestation key (AK).
 *
 * Verification (mirrors the native async path):
 * 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
 * 2. Check the quote's `extraData` equals `expected_report_data` (freshness),
 *    failing closed when an anchor is supplied and does not match.
 * 3. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
 * 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
 * 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
 *    SNP report signature, then enforce VMPL/debug/TCB policy and the optional
 *    minimum-TCB floor.
 * 6. When `crl_der` carries the AMD KDS CRL for the matched generation, verify
 *    its ARK signature and freshness, then check the VCEK against it —
 *    `collateral_verified` becomes `true`. Without it, revocation is skipped
 *    and `collateral_verified` stays `false`.
 *
 * - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
 * - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
 * - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
 * - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
 * - `crl_der`: optional DER AMD KDS CRL for the report's generation
 *
 * Returns the verification result as JSON, or throws on any check failure.
 * @param {string} evidence_json
 * @param {Uint8Array | null} [expected_report_data]
 * @param {Uint8Array | null} [expected_init_data_hash]
 * @param {string | null} [min_tcb_json]
 * @param {Uint8Array | null} [crl_der]
 * @returns {string}
 */
export function verify_az_snp(evidence_json, expected_report_data, expected_init_data_hash, min_tcb_json, crl_der) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(evidence_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(expected_report_data) ? 0 : passArray8ToWasm0(expected_report_data, wasm.__wbindgen_malloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(expected_init_data_hash) ? 0 : passArray8ToWasm0(expected_init_data_hash, wasm.__wbindgen_malloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(min_tcb_json) ? 0 : passStringToWasm0(min_tcb_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(crl_der) ? 0 : passArray8ToWasm0(crl_der, wasm.__wbindgen_malloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.verify_az_snp(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Verify Azure TDX (az-tdx) vTPM attestation evidence in WASM.
 *
 * The Azure TDX shape mirrors az-snp: the freshness anchor lives in the vTPM
 * quote's `extraData` (qualifyingData), while the Intel-signed TD quote's
 * `report_data` binds the vTPM attestation key (AK). Verification order
 * (see `platforms/az_tdx/verify.rs`):
 * 1. Parse the HCL report and require `report_type == TDX`.
 * 2. Verify the vTPM quote signature with the AK extracted from HCL var_data.
 * 3. Check the quote's `extraData` equals `expected_report_data` (freshness),
 *    failing closed when an anchor is supplied and does not match.
 * 4. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
 * 5. Parse the TD quote, verify its ECDSA signature, and verify the DCAP chain
 *    to the pinned Intel SGX Root CA.
 * 6. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
 * 7. Bind the AK to the TEE: `td_report.report_data[..32] == SHA-256(var_data)`.
 *
 * Like [`verify_az_snp`], the DCAP **collateral** checks (PCK CRL, TCB status,
 * TD-QE identity) need an async provider and are skipped in WASM, so
 * `collateral_verified` is always `false`. The measurement surfaces as
 * `claims.launch_digest` = hex(MRTD); MRTD/RTMR pinning is the JS policy
 * layer's job (a mismatch is reported, not fatal, in the core).
 *
 * - `evidence_json`: az-tdx evidence JSON (`{ version, tpm_quote, hcl_report, td_quote }`)
 * - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
 * - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
 *
 * Unlike [`verify_tdx`], this entry point has **no `expected_rtmr3`
 * parameter and enforces no RTMR[3] pin** — do not assume parity. The az-tdx
 * core computes `rtmr3_match` the same way, so extending this entry point is
 * a known follow-up; until then an az-tdx caller cannot pin deployment
 * identity here.
 *
 * Returns the verification result as JSON, or throws on any check failure.
 *
 * This is `async` (unlike `verify_az_snp`, whose core is sync) because the
 * shared az-tdx core is `async` for its optional collateral provider; with a
 * `None` provider it performs no actual awaiting. Callers `await` the returned
 * Promise.
 * @param {string} evidence_json
 * @param {Uint8Array | null} [expected_report_data]
 * @param {Uint8Array | null} [expected_init_data_hash]
 * @returns {Promise<string>}
 */
export function verify_az_tdx(evidence_json, expected_report_data, expected_init_data_hash) {
    const ptr0 = passStringToWasm0(evidence_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(expected_report_data) ? 0 : passArray8ToWasm0(expected_report_data, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(expected_init_data_hash) ? 0 : passArray8ToWasm0(expected_init_data_hash, wasm.__wbindgen_malloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.verify_az_tdx(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Verify live SNP evidence in WASM.
 *
 * Enforces the same endorsement-key and platform-security policy as the
 * native SNP verifier (`platforms/snp/verify.rs`), minus only VEK fetching
 * (the VEK must be inline). The one intentional difference from the generic
 * [`verify`] entry point is the explicit `generation` argument: v2 reports
 * (Azure HCL evidence unwrapped to a bare report) carry no CPUID fields to
 * auto-detect from, so the caller declares the generation and the VEK chain
 * check authenticates it — a wrong declaration fails its own chain.
 *
 * Checks, in native order: ARK → ASK/ASVK → VEK chain against the bundled
 * roots (VLEK auto-detected), VEK validity period, optional CRL revocation,
 * report signature, VMPL == 0, debug-policy rejection (no opt-in here; fail
 * closed), VEK chip-id/TCB OID cross-validation against the report, and the
 * optional minimum-TCB floor.
 *
 * Collateral: when `crl_der` carries the AMD KDS CRL for this generation,
 * its signature is verified against the bundled ARK and its
 * thisUpdate/nextUpdate window against the current time, then the VEK is
 * checked against it and the result's `collateral_verified` is `true`.
 * Without it, revocation is skipped and `collateral_verified` is `false` —
 * surfaced, never silently upgraded.
 *
 * - `evidence_json`: evidence JSON with inline cert_chain.vcek
 * - `generation`: processor generation ("milan", "genoa", "turin")
 * - `expected_report_data`: optional raw bytes to check against report_data
 *   in the report (comparison reported as `report_data_match`, not fatal —
 *   the policy layer decides)
 * - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON); a
 *   reported TCB below any component fails closed
 * - `crl_der`: optional DER AMD KDS CRL for this generation
 *
 * Returns verification result as JSON.
 * @param {string} evidence_json
 * @param {string} generation
 * @param {Uint8Array | null} [expected_report_data]
 * @param {string | null} [min_tcb_json]
 * @param {Uint8Array | null} [crl_der]
 * @returns {string}
 */
export function verify_snp(evidence_json, generation, expected_report_data, min_tcb_json, crl_der) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(evidence_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(generation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(expected_report_data) ? 0 : passArray8ToWasm0(expected_report_data, wasm.__wbindgen_malloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(min_tcb_json) ? 0 : passStringToWasm0(min_tcb_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(crl_der) ? 0 : passArray8ToWasm0(crl_der, wasm.__wbindgen_malloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.verify_snp(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Verify bare-metal Intel TDX (tdx) DCAP attestation evidence in WASM.
 *
 * This is the direct-DCAP counterpart of [`verify_az_tdx`]: no vTPM in the
 * path, so the freshness anchor lives directly in the TD quote's 64-byte
 * `report_data` (zero-padded), as produced by attesters that bind
 * `SHA-384(anchor)` — e.g. a serving-cert SPKI + nonce, or a session
 * public key + nonce. Verification (see `platforms/tdx/verify.rs`):
 * 1. Parse the TD quote (v4/v5) and verify its ECDSA P-256 signature.
 * 2. Verify the full DCAP chain: PCK cert chain to the pinned Intel SGX Root
 *    CA, QE report signature, and QE report binding.
 * 3. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
 * 4. Bind `report_data` to `expected_report_data` (padded, constant-time),
 *    failing closed when an anchor is supplied and does not match.
 * 5. Optionally bind MRCONFIGID to `expected_init_data_hash`.
 * 6. When the evidence carries a `cc_eventlog`, replay it against the RTMRs:
 *    RTMR[0-2] divergence fails closed; RTMR[3] divergence only warns, because
 *    runtime extends after the log was captured are expected there (see
 *    `platforms/tdx/ccel.rs`).
 * 7. When `expected_rtmr3` is supplied, require the TD's RTMR[3] to match it.
 *
 * Like the other vTPM-less entry points, the DCAP **collateral** checks (PCK
 * CRL, TCB status, TD-QE identity) need an async provider and are skipped in
 * WASM, so `collateral_verified` is always `false`. The measurement surfaces
 * as `claims.launch_digest` = hex(MRTD); MRTD pinning is the JS policy
 * layer's job.
 *
 * - `evidence_json`: tdx evidence JSON (`{ quote, cc_eventlog? }`, base64 std)
 * - `expected_report_data`: optional raw bytes the TD quote `report_data`
 *   must equal after zero-padding to 64 bytes
 * - `expected_init_data_hash`: optional bytes to bind against MRCONFIGID
 * - `expected_rtmr3`: optional 48 raw bytes the TD's RTMR[3] must equal
 *
 * RTMR[3] is the runtime measurement register: unlike MRTD it is extended
 * after launch, so it can carry deployment identity a launch measurement
 * cannot — on a c8s node, the operator-key seed plus any per-workload
 * extends. Pinning it is what distinguishes *this* cluster from anyone
 * else's genuine instance of the same audited image. It is not replayable
 * from the CCEL by construction (see `platforms/tdx/ccel.rs`), which is why
 * it must be supplied rather than derived.
 *
 * Unlike [`VerifyParams::expected_rtmr3`], which only *reports* the
 * comparison via `rtmr3_match`, this entry point **fails closed**: a
 * mismatch throws, matching how `expected_report_data` behaves here. A
 * browser policy layer that forwarded the pin but forgot to inspect
 * `rtmr3_match` would otherwise silently accept any node.
 *
 * Returns the verification result as JSON, or throws on any check failure.
 *
 * `async` for the same reason as [`verify_az_tdx`]: the shared core is
 * `async` for its optional collateral provider; with a `None` provider it
 * performs no actual awaiting. Callers `await` the returned Promise.
 * @param {string} evidence_json
 * @param {Uint8Array | null} [expected_report_data]
 * @param {Uint8Array | null} [expected_init_data_hash]
 * @param {Uint8Array | null} [expected_rtmr3]
 * @returns {Promise<string>}
 */
export function verify_tdx(evidence_json, expected_report_data, expected_init_data_hash, expected_rtmr3) {
    const ptr0 = passStringToWasm0(evidence_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(expected_report_data) ? 0 : passArray8ToWasm0(expected_report_data, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(expected_init_data_hash) ? 0 : passArray8ToWasm0(expected_init_data_hash, wasm.__wbindgen_malloc);
    var len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(expected_rtmr3) ? 0 : passArray8ToWasm0(expected_rtmr3, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.verify_tdx(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_bce6d499ff0a4aff: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_is_function_5cd60d5cf78b4eef: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_undefined_35bb9f4c7fd651d5: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_9c31b086c2b26051: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_3fa391f3fcdb55f8: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_call_dfde26266607c996: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_getTime_09f1dd40a44edb30: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_new_0_2722fcdb71a888a6: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_typed_c072c4ce9a2a0cdf: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h1c005da840836e19(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_queueMicrotask_78d584b53af520f5: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_b39ea83c7f01971a: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_resolve_d17db9352f5a220e: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_9b2406c23aeb2023: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_b34d2126934e16ba: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_then_837494e384b37459: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 392, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h930b9d8ef23db674);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./attestation_wasm_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__h930b9d8ef23db674(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h930b9d8ef23db674(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h1c005da840836e19(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h1c005da840836e19(arg0, arg1, arg2, arg3);
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('attestation_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
