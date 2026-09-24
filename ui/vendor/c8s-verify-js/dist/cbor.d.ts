/** Any value the codec can round-trip. */
export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | {
    [key: string]: CborValue;
};
/**
 * Encode a JS value to CBOR bytes.
 */
export declare function cborEncode(value: unknown): Uint8Array;
/**
 * Decode CBOR bytes to a JS value. Byte strings decode to Uint8Array, text strings
 * to string, maps to plain objects.
 */
export declare function cborDecode(bytes: Uint8Array): CborValue;
//# sourceMappingURL=cbor.d.ts.map