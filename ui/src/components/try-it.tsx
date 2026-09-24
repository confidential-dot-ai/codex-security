import { DEPLOYMENT, PINS, SITE } from "@/lib/config";
import { CopyButton } from "./copy-button";

const EP = SITE.defaultEndpoint;

function Block({ title, body, code, caution }: { title: string; body: string; code: string; caution?: string }) {
  return (
    <div className="mb-6">
      <h3 className="mb-1 text-[1.02rem] font-semibold text-heading">{title}</h3>
      <p className="mb-2 max-w-[72ch] text-[0.9rem] leading-relaxed text-foreground">{body}</p>
      <div className="code-block">
        <CopyButton text={code} />
        <pre>
          <code>{code}</code>
        </pre>
      </div>
      {caution && (
        <p className="-mt-2 max-w-[72ch] text-[0.82rem] leading-relaxed text-warn">{caution}</p>
      )}
    </div>
  );
}

/** Everything this page does, done from a terminal instead. */
export function TryIt() {
  return (
    <section className="mt-12 border-t border-border pt-8" id="try-it">
      <p className="mb-1 font-mono text-[0.68rem] uppercase tracking-[0.15em] text-accent">
        do not take our word for it
      </p>
      <h2 className="mb-2 text-2xl font-semibold tracking-[0.01em] text-heading">
        Try it yourself
      </h2>
      <p className="mb-6 max-w-[72ch] text-[0.95rem] leading-relaxed text-foreground">
        Nothing above is privileged to this page. The same attestation is available to any client,
        and the verifier is open source. What follows checks the endpoint from a terminal and then
        uses it.
      </p>

      <Block
        title="1. Take the anchors with you"
        body="The pins must not come from the endpoint under test. These are the exact values this page enforces, written into the manifest format c8s verify reads — so the command below checks the same thing the cascade above checked. The mesh CA is fetched here for convenience; it is an operator's statement, so treat a fetched copy as unverified until it matches the one you were given."
        code={`cat > manifest.json <<'EOF'\n{\n  "tdx": {\n    "mrtd":  "${PINS.mrtd}",\n    "rtmr1": "${PINS.rtmr1}",\n    "rtmr2": "${PINS.rtmr2}"\n  }\n}\nEOF\n\n# the cluster identity anchor — compare against your operator's copy\ncurl -s ${EP}/.well-known/mesh-ca.pem -o mesh-ca.pem`}
      />

      <Block
        title="2. Verify the endpoint"
        body="c8s verify does what this page does, in a terminal: a fresh nonce-bound TDX quote, the DCAP chain, the register pins, and the serving leaf chained to your mesh CA. Use the attest-pq path with --kind lb; it binds the leaf that actually serves the connection. The default discovery mode fails here by construction, because it attests the CDS-issued mesh certificate while the wire serves the Let's Encrypt one. Change one hex digit in manifest.json and it fails closed, which is the point."
        code={`c8s verify ${EP} \\\n  --mode attest-pq --kind lb \\\n  --image-manifest manifest.json \\\n  --mesh-ca mesh-ca.pem`}
      />

      <Block
        title="3. Read the admission allowlist"
        body="The cluster admits only the image digests in this document, and admission does not rely on the control plane. Served here for convenience; pin the canonical bytes out of band if you want it to be an anchor rather than a claim."
        code={`curl -s ${EP}/allowlist | jq '.workloads | keys'\n\n# the digest to compare against the operator's canonical copy\ncurl -s ${EP}/allowlist | shasum -a 256`}
      />

      <Block
        title="4. Submit a scan"
        body="The scan API takes a repository and an optional full 40-character commit SHA; leave the revision out and the service resolves HEAD. The repository is cloned and scanned inside the enclave."
        code={`TOK=<your /v1/scans bearer token>\n\ncurl -s -X POST ${EP}/v1/scans \\\n  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \\\n  -d '{"repository":"https://github.com/octocat/Hello-World"}'\n\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans/<id>\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans/<id>/log\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans/<id>/files`}
        caution="These curl calls ride ordinary TLS, so the token and the findings are readable to whatever terminates it. That is exactly what this page avoids: it seals every request to the attested enclave instead. Use curl to convince yourself the endpoint is real; use the console when the contents matter."
      />

      <div className="mb-2">
        <h3 className="mb-1 text-[1.02rem] font-semibold text-heading">The findings dashboard</h3>
        <p className="max-w-[72ch] text-[0.9rem] leading-relaxed text-foreground">
          codex-security ships its own dashboard over stored findings, served by the same process.
          It is upstream, not part of this console.{" "}
          <a href={`${EP}${DEPLOYMENT.dashboardPath}`} target="_blank" rel="noreferrer">
            Open the dashboard
          </a>
          .
        </p>
        <p className="mt-1 max-w-[72ch] text-[0.82rem] leading-relaxed text-warn">
          It loads over ordinary TLS, outside the attested channel, and it is not gated by the
          verification above.
        </p>
      </div>
    </section>
  );
}
