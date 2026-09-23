import type { NextConfig } from "next";

// Fully static export: the verification runs entirely in the browser. No
// server APIs, no telemetry. The vendored c8s-verify library loads its WASM
// verifier via new URL(..., import.meta.url), which the bundler emits as a
// static asset.
const nextConfig: NextConfig = {
  output: "export",
};

export default nextConfig;
