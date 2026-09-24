/**
 * A TDX guest-image pin: MRTD + RTMR[1] + RTMR[2] as one tuple, each exactly
 * 96 lowercase hex chars (48 bytes, SHA-384).
 */
export interface TdxImage {
    /** TDVF firmware measurement (surfaces as `claims.launch_digest`). */
    mrtd: string;
    /** Guest kernel / UKI image identity (`claims.platform_data.rtmr_1`). */
    rtmr1: string;
    /** Guest rootfs / UKI section chain (`claims.platform_data.rtmr_2`). */
    rtmr2: string;
}
/**
 * Validate a caller-supplied tuple (e.g. `VerifyPolicy.tdxImage`) with the
 * same strictness as {@link parseImageManifest}: all three registers or
 * nothing — a partial tuple would silently verify only part of the image.
 */
export declare function requireTdxImage(context: string, tuple: TdxImage): TdxImage;
/**
 * Parse a published TDX image manifest — a JSON object carrying "mrtd",
 * "rtmr1", and "rtmr2", each exactly 96 lowercase hex chars — into the tuple
 * {@link VerifyPolicy.tdxImage} pins. A missing or malformed field fails the
 * whole parse, so a policy can never end up pinning part of an image; unknown
 * extra fields are allowed (build manifests carry other data). Feed it the
 * manifest file bytes verbatim.
 */
export declare function parseImageManifest(jsonBytes: Uint8Array | string): TdxImage;
//# sourceMappingURL=manifest.d.ts.map