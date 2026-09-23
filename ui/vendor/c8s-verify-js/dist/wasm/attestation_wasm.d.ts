/* tslint:disable */
/* eslint-disable */

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
 */
export function verify(envelope_json: string, expected_report_data?: Uint8Array | null, expected_init_data_hash?: Uint8Array | null, min_tcb_json?: string | null, snp_crl_der?: Uint8Array | null): Promise<string>;

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
 */
export function verify_az_snp(evidence_json: string, expected_report_data?: Uint8Array | null, expected_init_data_hash?: Uint8Array | null, min_tcb_json?: string | null, crl_der?: Uint8Array | null): string;

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
 */
export function verify_az_tdx(evidence_json: string, expected_report_data?: Uint8Array | null, expected_init_data_hash?: Uint8Array | null): Promise<string>;

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
 */
export function verify_snp(evidence_json: string, generation: string, expected_report_data?: Uint8Array | null, min_tcb_json?: string | null, crl_der?: Uint8Array | null): string;

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
 */
export function verify_tdx(evidence_json: string, expected_report_data?: Uint8Array | null, expected_init_data_hash?: Uint8Array | null, expected_rtmr3?: Uint8Array | null): Promise<string>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => any;
    readonly verify_az_snp: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly verify_az_tdx: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly verify_snp: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly verify_tdx: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly wasm_bindgen__convert__closures_____invoke__h930b9d8ef23db674: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h1c005da840836e19: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
