import { SITE } from "@/lib/config";
import { CopyButton } from "./copy-button";

const EP = SITE.defaultEndpoint;

function Block({
  title,
  body,
  code,
  caution,
}: {
  title: string;
  body: string;
  code: string;
  caution?: string;
}) {
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

/** The same evidence this page uses, from a terminal. */
export function TryIt() {
  return (
    <section className="mt-12 border-t border-border pt-8" id="try-it">
      <h2 className="mb-2 text-2xl font-semibold tracking-[0.01em] text-heading">
        Try it yourself
      </h2>
      <p className="mb-6 max-w-[72ch] text-[0.95rem] leading-relaxed text-foreground">
        Nothing above is privileged to this page. The endpoint hands the same evidence to anyone
        who asks.
      </p>

      <Block
        title="1. Ask for a fresh attestation"
        body="The nonce is yours, so the evidence that comes back was produced for this request and cannot be a replay of an earlier one."
        code={`NONCE=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')\n\ncurl -s "${EP}/.well-known/c8s/attest-lb?nonce=$NONCE" -o attestation.json`}
      />

      <Block
        title="2. Look at what came back"
        body="A TDX quote and its event log, the certificate chain, and the proof binding the leaf that served you. Reading these fields is not verifying them — that is the signature checking this page just did in WebAssembly, or c8s verify on the command line."
        code={`jq '{version, platform, front_door_mode, nonce, serving_leaf_sha256}' attestation.json\n\n# the nonce you sent must come back unchanged\necho $NONCE`}
      />

      <Block
        title="3. Submit a scan"
        body="A repository, and optionally a full 40-character commit SHA; leave it out and the service resolves HEAD. The clone and the scan happen inside the enclave."
        code={`TOK=<your /v1/scans bearer token>\n\ncurl -s -X POST ${EP}/v1/scans \\\n  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \\\n  -d '{"repository":"https://github.com/octocat/Hello-World"}'\n\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans\ncurl -s -H "Authorization: Bearer $TOK" ${EP}/v1/scans/<id>/log`}
        caution="These calls ride ordinary TLS, so the token and the findings are readable to whatever terminates it. That is what this console avoids: it seals every request to the attested enclave instead."
      />
    </section>
  );
}
