// Typed errors for the c8s-verify flow. Codes mirror the c8s error envelope
// (pkg/types/error_codes.go) where they overlap, plus client-side codes for
// checks the browser performs that the server never sees.
export class C8sVerifyError extends Error {
    code;
    details;
    constructor(code, message, opts = {}) {
        super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
        this.name = "C8sVerifyError";
        this.code = code;
        this.details = opts.details ?? {};
    }
}
/**
 * Helper to throw a typed error in one expression.
 */
export function fail(code, message, opts) {
    throw new C8sVerifyError(code, message, opts);
}
//# sourceMappingURL=errors.js.map