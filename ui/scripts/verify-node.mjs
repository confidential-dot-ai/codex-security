// Run the same verification the page runs, from Node, against a live endpoint.
//
//   npm run verify:node                 # the endpoint and pins from config.ts
//   npm run verify:node -- http://localhost:8443   # e.g. through the dev proxy
//   TOK=<bearer> npm run verify:node    # also list scans over the tunnel
//
// The pins and the endpoint are read out of src/lib/config.ts, so this cannot
// drift from what the page enforces. It is the quickest way to tell a protocol
// or pin problem from a browser problem.

import { readFileSync } from "node:fs";
import { C8sClient } from "c8s-verify";

const config = readFileSync(new URL("../src/lib/config.ts", import.meta.url), "utf8");

const pick = (key) => {
  const m = new RegExp(`${key}:\\s*\n?\\s*"([0-9a-f]{96})"`).exec(config);
  if (!m) throw new Error(`could not read ${key} from config.ts`);
  return m[1];
};
const PINS = { mrtd: pick("mrtd"), rtmr1: pick("rtmr1"), rtmr2: pick("rtmr2") };
const MESH_CA_PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/.exec(config)[0];
const ENDPOINT =
  process.argv[2] ?? /endpoint:\s*"([^"]+)"/.exec(config)[1];

const client = new C8sClient({
  baseUrl: ENDPOINT,
  platform: "tdx",
  requireFreshness: true,
  measurements: [PINS.mrtd],
  tdxImage: PINS,
  meshCaPem: MESH_CA_PEM,
});

try {
  const session = await client.connect();
  const a = session.attestation;
  console.log("VERIFIED", {
    endpoint: ENDPOINT,
    platform: a.platform,
    trustClass: a.trustClass,
    frontDoorMode: a.frontDoorMode,
    measurement: a.measurement,
    rtmr1: a.claims?.platform_data?.rtmr_1,
    rtmr2: a.claims?.platform_data?.rtmr_2,
    issuerCN: a.cert?.issuerCN,
    sessionId: session.sessionId,
    warnings: a.warnings,
  });
  const headers = process.env.TOK ? { Authorization: `Bearer ${process.env.TOK}` } : {};
  const res = await session.fetch("/v1/scans", { headers });
  console.log("tunnel /v1/scans ->", res.status, res.text().slice(0, 200));
} catch (e) {
  console.error("FAILED", e?.code ?? "", e?.message ?? e);
  process.exitCode = 1;
}
