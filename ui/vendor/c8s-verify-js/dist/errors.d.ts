export type C8sErrorCode = "invalid_request" | "nonce_mismatch" | "verification_failed" | "report_data_mismatch" | "measurement_denied" | "measurement_incomplete" | "rtmr_denied" | "rtmr3_denied" | "invalid_cert" | "cert_chain" | "identity_binding" | "key_binding" | "channel_error" | "workload_not_attested" | "workload_invalid" | "workload_denied" | "workload_unresolved" | "allowlist_denied" | "unsupported";
export interface C8sErrorOptions {
    cause?: unknown;
    details?: Record<string, unknown>;
}
export declare class C8sVerifyError extends Error {
    readonly code: C8sErrorCode;
    readonly details: Record<string, unknown>;
    constructor(code: C8sErrorCode, message: string, opts?: C8sErrorOptions);
}
/**
 * Helper to throw a typed error in one expression.
 */
export declare function fail(code: C8sErrorCode, message: string, opts?: C8sErrorOptions): never;
//# sourceMappingURL=errors.d.ts.map