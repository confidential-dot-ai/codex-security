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
`vercel.json` pins `outputDirectory: "out"`; set the Vercel Root Directory to
this folder. Follows the pattern of
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

The serving certificate is CDS-issued and attestation-bound, not WebPKI, so a
browser will not trust it on sight. Open the endpoint in a tab once and accept
its certificate before connecting; otherwise the fetch fails before any
attestation happens and the cascade reports a connection error.

```bash
npm install
npm run dev     # http://localhost:3000
```

Enter the endpoint, paste the API token (held in the tab only — never stored),
review the pins, then **Verify and connect**.

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

## Talking to the cluster from a browser

Two properties of the deployment shape the UI, both measured against the live
endpoint:

- The serving certificate is CDS-issued and attestation-bound, so a browser
  blocks `fetch()` to the origin until the tab has opened it once and accepted
  the interstitial. A failure at that point happens *before any attestation
  ran*, so the page reports it as a connection error, never as a verdict.
- `/v1/scans` answers a direct browser call with `401` and no CORS headers at
  all, so direct calls can never work. Every API call therefore rides the
  attested tunnel, which is also what keeps the token sealed.
