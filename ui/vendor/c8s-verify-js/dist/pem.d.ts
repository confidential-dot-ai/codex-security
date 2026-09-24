/**
 * Decode all PEM blocks of the given label from a string.
 * @returns DER bodies, in order
 */
export declare function decodePEM(pem: string, label?: string): Uint8Array[];
/**
 * Decode exactly one PEM block, throwing if zero or more than one is present.
 */
export declare function decodeOnePEM(pem: string, label?: string): Uint8Array;
/**
 * Encode DER bytes as a PEM block.
 */
export declare function encodePEM(der: Uint8Array, label?: string): string;
//# sourceMappingURL=pem.d.ts.map