// Local development proxy for the attested endpoint.
//
//   npm run proxy                      # http://localhost:8443 -> the endpoint
//   C8S_TARGET=https://host:port npm run proxy
//
// Why this exists: the endpoint's serving certificate is CDS-issued and
// attestation-bound, not WebPKI, so a browser refuses it until the user has
// opened the origin in a tab and accepted it. That is a poor local loop and, in
// some browsers, surfaces only as an opaque "NetworkError".
//
// Proxying does not weaken the check. Verification never trusted the TLS chain:
// it verifies a nonce-bound TDX quote and the mesh identity proof carried inside
// the attestation bundle, against pins this page holds out of band. A proxy in
// the middle sees exactly what a TLS-terminating load balancer already sees —
// which is the threat the over-encrypted channel exists to answer, and the
// channel is established end to end through this proxy, not with it.
//
// Development only. Never point a deployed page at a proxy.

import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";

const TARGET = new URL(process.env.C8S_TARGET ?? "https://15.204.104.35:30443");
const PORT = Number(process.env.PORT ?? 8443);

const server = createServer((req, res) => {
  // The browser's preflight never reaches the endpoint; answer it here.
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": req.headers.origin ?? "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "Authorization, Content-Type, X-C8s-Session",
      "access-control-max-age": "600",
    });
    res.end();
    return;
  }

  const upstream = httpsRequest(
    {
      protocol: TARGET.protocol,
      hostname: TARGET.hostname,
      port: TARGET.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: TARGET.host },
      // The certificate is attestation-bound, not WebPKI; Node cannot chain it
      // and the attestation is what decides trust.
      rejectUnauthorized: false,
    },
    (up) => {
      res.writeHead(up.statusCode ?? 502, {
        ...up.headers,
        "access-control-allow-origin": req.headers.origin ?? "*",
      });
      up.pipe(res);
    },
  );

  upstream.on("error", (e) => {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "proxy_error", message: String(e?.message ?? e) }));
  });

  req.pipe(upstream);
});

server.listen(PORT, () => {
  console.log(`dev proxy: http://localhost:${PORT} -> ${TARGET.origin}`);
  console.log("point the endpoint field at http://localhost:" + PORT);
});
