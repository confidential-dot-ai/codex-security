import { type InitInput } from "./wasm/attestation_wasm.js";
import { type Evidence } from "./hcl.js";
/**
 * Initialise the WASM module exactly once. Optionally pass an explicit init input
 * (BufferSource, URL, Response, or WebAssembly.Module) to override discovery.
 */
export declare function initVerifier(input?: InitInput): Promise<void>;
/**
 * Call the SNP verifier. Initialises the module on first use. Accepts both
 * bare SNP evidence and az-snp (Azure HCL-wrapped) evidence; the latter is
 * unwrapped to the raw SNP report the WASM verifier understands.
 * @param evidence bare SNP or az-snp evidence
 * @param generation "milan" | "genoa" | "turin"
 * @returns verification result JSON (or throws on HW/chain failure)
 */
export declare function verifySnp(evidence: Evidence, generation: string, expectedReportData?: Uint8Array): Promise<string>;
/**
 * Call the az-snp verifier: full Azure SEV-SNP verification including the vTPM
 * quote. Unlike {@link verifySnp}, the evidence is NOT unwrapped to a bare SNP
 * report — the HCL report, VCEK, and TPM quote are all verified together. The
 * freshness anchor (`expectedReportData`) is checked against the TPM quote's
 * extraData, not the SNP report_data (which instead binds the vTPM AK).
 *
 * The processor generation is auto-detected from the report CPUID, so no
 * generation argument is needed.
 *
 * @param evidenceJson az-snp evidence: { version, tpm_quote, hcl_report, vcek }
 * @param expectedReportData raw bytes the TPM quote extraData must equal
 * @param expectedInitDataHash 32-byte hash to bind against PCR[8]
 * @returns verification result JSON (or throws on any failure)
 */
export declare function verifyAzSnp(evidenceJson: string, expectedReportData?: Uint8Array, expectedInitDataHash?: Uint8Array): Promise<string>;
/**
 * Call the az-tdx verifier: full Azure TDX verification. Like {@link verifyAzSnp},
 * the evidence is passed through unwrapped — the HCL report, TD quote, and vTPM
 * quote are verified together. The freshness anchor (`expectedReportData`) is
 * checked against the TPM quote's extraData (the TD quote's report_data instead
 * binds the vTPM AK). The measurement surfaces as `claims.launch_digest` = hex(MRTD).
 *
 * The underlying WASM export is async (the shared az-tdx core is async for its
 * optional DCAP collateral provider, which is skipped here), so this awaits it.
 *
 * @param evidenceJson az-tdx evidence: { version, tpm_quote, hcl_report, td_quote }
 * @param expectedReportData raw bytes the TPM quote extraData must equal
 * @param expectedInitDataHash 32-byte hash to bind against PCR[8]
 * @returns verification result JSON (or throws on any failure)
 */
export declare function verifyAzTdx(evidenceJson: string, expectedReportData?: Uint8Array, expectedInitDataHash?: Uint8Array): Promise<string>;
/**
 * Call the bare-metal tdx verifier: direct Intel TDX DCAP verification with no
 * vTPM in the path. The TD quote signature and the full DCAP chain (PCK chain
 * to the pinned Intel SGX Root CA, QE report signature and binding) are
 * verified in WASM, debug TDs are rejected, and — when the evidence carries a
 * `cc_eventlog` — the CCEL is replayed against RTMR0–3, failing closed on any
 * divergence. Unlike the vTPM platforms, the freshness anchor
 * (`expectedReportData`) is checked directly against the TD quote's 64-byte
 * `report_data` (zero-padded, constant-time). The measurement surfaces as
 * `claims.launch_digest` = hex(MRTD).
 *
 * The processor generation is irrelevant for TDX, so no generation argument is
 * needed. DCAP collateral checks (PCK CRL, TCB status, TD-QE identity) need an
 * async provider and are skipped in WASM: `collateral_verified` stays `false`.
 *
 * When `expectedRtmr3` is supplied the verifier additionally requires the TD's
 * RTMR[3] to equal it, and **throws** on a mismatch. RTMR[3] is extended after
 * launch (on a c8s node: the operator key bound at boot, plus any per-workload
 * measurements chained on), so unlike MRTD it identifies a specific deployment
 * rather than a build. It is not replayable from the CCEL by construction,
 * which is why it must be supplied rather than derived.
 *
 * @param evidenceJson tdx evidence: { quote, cc_eventlog? } (base64 std)
 * @param expectedReportData raw bytes the TD quote report_data must equal
 * @param expectedInitDataHash bytes to bind against MRCONFIGID
 * @param expectedRtmr3 48 raw bytes the TD's RTMR[3] must equal
 * @returns verification result JSON (or throws on any failure)
 */
export declare function verifyTdx(evidenceJson: string, expectedReportData?: Uint8Array, expectedInitDataHash?: Uint8Array, expectedRtmr3?: Uint8Array): Promise<string>;
//# sourceMappingURL=wasm-loader.d.ts.map