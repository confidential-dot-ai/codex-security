# codex-security · attested console

A browser console for the scan API added in `sdk/typescript/src/server/scans.ts`,
for deployments where that API runs as a confidential workload on a
[c8s](https://github.com/confidential-dot-ai/c8s) cluster.

It does two things, in this order:

1. **Verifies the endpoint in your browser.** It fetches a fresh
   nonce-bound Intel TDX quote, checks the DCAP certificate chain in
   WebAssembly, compares MRTD, RTMR[1] and RTMR[2] against pins you supply out
   of band, and checks the serving certificate chains to a mesh CA you pinned.
   No server of ours takes part in the checks.
2. **Submits scans through the channel that verification established.** Every
   request — method, path, headers, body, and your API token — is sealed to the
   attested enclave, so whatever terminates TLS in front of the cluster sees
   only ciphertext.

It is a static Next.js export: `npm install && npm run build`, output in `out/`.
Set the Vercel Root Directory to this folder. Follows the pattern of
[c8s-verify-poc](https://github.com/confidential-dot-ai/c8s-verify-poc).

## Why connect rather than just verify

`C8sClient.connect()` binds a fresh nonce and the derived channel keys into the
quote's `report_data`. A replayed quote therefore cannot carry a session, and
the thing you verified is the same thing you then talk to. Verifying once and
afterwards calling the endpoint normally would prove strictly less.

The console never marks a check passed that the library has not already made.
When verification fails, the cascade marks only the step that failed and leaves
everything below it unchecked, because nothing below it was proven.

## Pins

`src/lib/config.ts` holds the deployment profile. Everything in it is an
out-of-band anchor — what the browser trusts *before* it has spoken to the
cluster — so it must come from the node image's published `manifest.json` and
from an operator, never from the endpoint being verified.

| Pin | Where it comes from | What it covers |
| --- | --- | --- |
| MRTD | `manifest.json` → `tdx.mrtd` | TDVF firmware only — on TDX this alone does **not** pin the guest |
| RTMR[1] | `manifest.json` → `tdx.rtmr1` | the guest kernel |
| RTMR[2] | `manifest.json` → `tdx.rtmr2` | the kernel command line, which carries the dm-verity root hash |
| Mesh CA | the operator | this specific cluster, rather than some genuine TDX machine |

MRTD alone is not a sufficient policy, which is why the console pins the whole
tuple and `c8s verify` refuses a measurements-only pin on TDX. The pins panel
accepts a pasted `manifest.json` so a rebuilt cluster's values can be loaded
verbatim rather than transcribed.

## Running against a cluster

```bash
npm install
npm run dev     # http://localhost:3000
```

Open the trust page, click **Verify the cluster**, then go to the scan page and
paste the API token (held in the tab only — never stored).

The router terminates public TLS with a WebPKI certificate issued to its
in-guest ACME sidecar, so the browser trusts the endpoint outright and there is
nothing to accept by hand. The serving key stays inside the enclave, which is
why the endpoint still serves `attest-lb` — the binding to that exact serving
leaf. c8s serves it only for the TEE-held-key front doors (`cds` and `acme`),
never for `webpki`. The verified result carries which one you got, and the trust
page shows it.


## Pages

Two pages, sharing one verification session (the provider sits in the root
layout, so a session established on the trust page is the session the scan page
speaks over):

- **`/` — trust.** What the endpoint is, what gets checked and in what order,
  the live cascade, the verdict with measured-versus-pinned registers, the pins
  themselves, what is running behind the endpoint, and an explicit list of what
  the page does *not* prove.
- **`/scan` — scan.** Gated on a verified session. Token entry (tab only),
  submission, the job list, and per-job log tail, rendered report and artifacts.

Both follow the layout and palette of
[c8s-verify-poc](https://github.com/confidential-dot-ai/c8s-verify-poc)'s
`demo-app`, which is the house style for c8s verification pages.

## Layout

```
src/lib/config.ts        deployment profile, pins, manifest parsing
src/lib/verify-flow.ts   the verification flow and its UI-visible phases
src/lib/verify-context.tsx  one session shared by both pages
src/lib/api.ts           the scan API, spoken over the attested channel
src/components/          cascade, verdict, pins, scan console, markdown
vendor/c8s-verify-js     the verification library (MIT), vendored with its WASM
```

The library is vendored rather than depended on from a registry because it is
not published to npm and its git tree ships no build output; the WASM verifier
is built from Rust. `vendor/c8s-verify-js/LICENSE` travels with it.

Vendored at `c8s-verify-js` `d589419` (client-first X-Wing key exchange), built
with `npm run build:wasm && npm run build` in a checkout of that commit. The
vendored `package.json` adds subpath exports (`./keyagreement`, `./channel`,
`./base64`, `./xwing`, `./nonce`) that upstream does not publish, because
`verify-flow.ts` drives the same primitives `C8sClient.connect()` uses so the
cascade can resolve phase by phase. Nothing else in the package is modified.

`npm run verify:node` runs the same verification from Node against the live
endpoint, which is the quickest way to tell a protocol or pin problem from a
browser problem.

## Deploying

A static export (`output: "export"` in `next.config.ts`), so any static host can
serve `out/`. On Vercel set the **Root Directory** to `ui` and leave everything
else at the Next.js defaults — do not override the output directory. Vercel's
Next.js builder reads the export itself and looks for its own build manifests
under `.next`; pointing it at `out` makes it fail with a missing
`routes-manifest.json` *after* an otherwise successful build. Node 22.

Do **not** set `NEXT_PUBLIC_SCAN_TOKEN` on a deployment. Anything `NEXT_PUBLIC_*`
is compiled into the client bundle and readable by every visitor; it exists for
`.env.local` during development, and without it the page asks each visitor for
their own token.

The pins are compiled in at build time. A rebuilt cluster changes its RTMRs and
its mesh CA, so it needs a redeploy, not a reload — which is the intended
behaviour: a page that could silently adopt new pins would not be pinning
anything.

## Local loop: the dev proxy

Not needed against an `acme` front door, whose certificate the browser trusts.
It exists for a `cds` deployment, where the browser refuses the origin until the
tab has accepted the attestation-bound certificate by hand:

```bash
npm run proxy   # http://localhost:8443 -> the endpoint
npm run dev     # then put http://localhost:8443 in the endpoint field
```

This does not weaken the check. Verification never trusted the TLS chain: it
verifies a nonce-bound TDX quote and the mesh identity proof carried inside the
attestation bundle, against pins the page holds out of band, and the sealed
channel is established end to end through the proxy rather than with it. A proxy
sees exactly what the TLS-terminating load balancer already sees — which is the
threat the channel exists to answer. Development only; a deployed page must
point at the endpoint itself.


## Talking to the cluster from a browser

- `/v1/scans` answers a direct browser call with `401` and no CORS headers at
  all, so direct calls can never work. Every API call rides the attested tunnel,
  which is also what keeps the token sealed.
- Verification must use the `attest-pq` / `attest-lb` path, which is what
  `C8sClient.connect()` does. Under the ACME front door `c8s verify` in its
  default *discovery* mode fails by construction: discovery attests the
  CDS-issued mesh certificate while the wire serves the Let's Encrypt leaf, so
  their SHA-256s differ. Only `attest-pq` / `attest-lb` binds the leaf actually
  serving the connection, so a failing `c8s verify --mode discovery` says
  nothing about this page.
- A failure before any attestation ran is reported as a connection error, never
  as a verdict, and every request in the flow carries a 20s deadline.

