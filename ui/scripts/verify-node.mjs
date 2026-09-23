// Run the same verification the page runs, from Node, against a live endpoint.
//
//   NODE_TLS_REJECT_UNAUTHORIZED=0 node scripts/verify-node.mjs [endpoint]
//
// TLS is disabled deliberately: the serving certificate is CDS-issued and
// attestation-bound, not WebPKI, so Node cannot chain it — and the real check
// is the attestation below, not the TLS chain. A browser instead needs the tab
// to accept the certificate once.

import { C8sClient } from "c8s-verify";

const ENDPOINT = process.argv[2] ?? "https://15.204.104.35:30443";

const PINS = {
  mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  rtmr1:
    "3b260925fec6a0553b9a6aecf223a6ed1ddcbbee17df0b0e5c8bc056b0751c8530a83e71ed5b7ef9ff142ae842cdcecd",
  rtmr2:
    "eb120e4c57137f7a3f72c6ca3403d6f26da427df4ddcf0ed2580b72ab08a7a6078034c728a78e1153f77f199c9bbf615",
};

const MESH_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBqTCCAS+gAwIBAgIQDwFa3rbWAX/Q9O+vT+Ci6TAKBggqhkjOPQQDAzAWMRQw
EgYDVQQDEwtjOHMgTWVzaCBDQTAeFw0yNjA5MjMwNDMwMTRaFw0yNzA5MjMwNDMw
MTRaMBYxFDASBgNVBAMTC2M4cyBNZXNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEkKjY1skCZNhMSgN2DCmRW9lOSxG+0pQ6HNr09v9CqlgXm3YDvE9V8XssMLna
K8z53IHIwX3M4y9zJlEeiv/kEBsUoB95rfHytNgB+R5Mp8j2T5n6C36OmxDYmX6s
atXyo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUQUNZf7feLOUEdj4SbY95oULRD6QwCgYIKoZIzj0EAwMDaAAwZQIxALY/0wnH
W/OwswGZE1UZDnA0N0AwaLL+mxfrGXPUp+3oRq8YV6MafB8EuoxAPMwiggIwCrgj
TlKCWHwYJ1n3LKb38QwPtGGlUznyHCEP5oBnCeFuodtIdf4/V03chYz34o6A
-----END CERTIFICATE-----`;

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
    measurement: a.measurement,
    rtmr1: a.claims?.platform_data?.rtmr_1,
    rtmr2: a.claims?.platform_data?.rtmr_2,
    issuerCN: a.cert?.issuerCN,
    sessionId: session.sessionId,
    warnings: a.warnings,
  });
  const res = await session.fetch("/v1/scans");
  console.log("tunnel /v1/scans ->", res.status, res.text().slice(0, 120));
} catch (e) {
  console.error("FAILED", e?.code ?? "", e?.message ?? e);
  process.exitCode = 1;
}
