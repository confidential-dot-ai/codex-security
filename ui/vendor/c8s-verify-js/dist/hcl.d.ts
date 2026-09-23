/** Bare SEV-SNP evidence: the shape the WASM `verify_snp` entry consumes. */
export interface SnpEvidence {
    attestation_report: string;
    cert_chain: {
        vcek: string;
    };
}
/** Azure HCL-wrapped (az-snp) evidence, as emitted by the c8s Go extractor. */
export interface AzSnpEvidence {
    version?: string;
    tpm_quote?: unknown;
    hcl_report?: string;
    vcek?: string;
}
/** Azure TDX (az-tdx) vTPM evidence: HCL-wrapped TD report + vTPM quote + TD quote. */
export interface AzTdxEvidence {
    version?: number;
    tpm_quote?: unknown;
    hcl_report?: string;
    td_quote?: string;
}
/** Bare-metal Intel TDX (tdx) DCAP evidence: raw TD quote + optional CC event log. */
export interface TdxEvidence {
    quote: string;
    cc_eventlog?: string;
}
/** Any evidence shape the verifier layer can accept. */
export type Evidence = SnpEvidence | AzSnpEvidence | AzTdxEvidence | TdxEvidence;
/**
 * Extract the raw 1184-byte SNP attestation report from an Azure HCL report.
 * Validates the magic, hardware report type, and length before slicing.
 * @param hcl decoded HCL report bytes
 * @returns the 1184-byte SNP ATTESTATION_REPORT
 */
export declare function snpReportFromHcl(hcl: Uint8Array): Uint8Array;
/**
 * Convert az-snp evidence (HCL report + VCEK) into the bare-SNP evidence shape
 * the WASM verifier expects: `{ attestation_report, cert_chain: { vcek } }`,
 * both standard base64. The TPM quote and version are dropped — the WASM
 * verifies the hardware report only (see module note).
 */
export declare function hclEvidenceToSnp(evidence: AzSnpEvidence): SnpEvidence;
/**
 * Normalize an evidence object to the bare-SNP shape the WASM verifier accepts.
 * az-snp evidence (carries `hcl_report`) is unwrapped; bare SNP evidence
 * (carries `attestation_report`) is returned unchanged.
 */
export declare function toWasmEvidence(evidence: Evidence): SnpEvidence;
//# sourceMappingURL=hcl.d.ts.map