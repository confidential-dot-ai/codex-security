export declare const TAG: {
    readonly BOOLEAN: 1;
    readonly INTEGER: 2;
    readonly BIT_STRING: 3;
    readonly OCTET_STRING: 4;
    readonly NULL: 5;
    readonly OID: 6;
    readonly UTF8_STRING: 12;
    readonly SEQUENCE: 48;
    readonly SET: 49;
    readonly PRINTABLE_STRING: 19;
    readonly IA5_STRING: 22;
    readonly UTC_TIME: 23;
    readonly GENERALIZED_TIME: 24;
};
export interface DERNode {
    tag: number;
    constructed: boolean;
    start: number;
    headerLen: number;
    contentStart: number;
    contentEnd: number;
    end: number;
    bytes: Uint8Array;
    content: Uint8Array;
}
/**
 * Read one TLV element starting at `offset`.
 */
export declare function readTLV(buf: Uint8Array, offset: number): DERNode;
/**
 * Read all child TLVs of a constructed node.
 */
export declare function readChildren(buf: Uint8Array, node: DERNode): DERNode[];
/**
 * Decode an OID node's content into dotted-decimal string.
 */
export declare function decodeOID(content: Uint8Array): string;
/**
 * Assert that a node's length is written the one way DER permits.
 *
 * DER's whole promise is that a value has exactly one encoding, but readTLV is
 * permissive about *how* a length is written — 0x81 0xAD and 0x82 0x00 0xAD
 * both decode to 173. For most parsing that laxity is harmless. It is not for
 * attested extensions: the trust chain vouches for the exact extension bytes,
 * so "these bytes mean this value" has to be a bijection. Go buys the same
 * property with a byte-exact re-encode round-trip and calls the strictness
 * load-bearing; this states the rule directly instead.
 */
export declare function requireMinimalLength(node: DERNode, what: string): void;
/**
 * Parse a DER time (UTCTime or GeneralizedTime) into a Date.
 */
export declare function decodeTime(node: DERNode): Date;
//# sourceMappingURL=asn1.d.ts.map