export declare const bytesToBase64: (b: Uint8Array) => string;
export declare const bytesToBase64Url: (b: Uint8Array) => string;
export declare const base64ToBytes: (s: string) => Uint8Array;
export declare const base64UrlToBytes: (s: string) => Uint8Array;
export declare function bytesToHex(b: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function utf8ToBytes(s: string): Uint8Array;
export declare function bytesToUtf8(b: Uint8Array): string;
/**
 * Concatenate byte arrays.
 */
export declare function concatBytes(...parts: Uint8Array[]): Uint8Array;
/**
 * Constant-time equality for two byte arrays.
 */
export declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
//# sourceMappingURL=base64.d.ts.map