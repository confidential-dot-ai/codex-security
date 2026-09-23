# codex-security endpoint handoff (for the console UI)

Handoff for the browser console being built against the live scan API. Delivered
via git because rsync collect was failing. Everything here is public-by-design
(published node-image measurements, the mesh CA the router serves to anyone, a
public GHCR image) **except the API bearer token, which is deliberately not in
this file** — see [Bearer token](#bearer-token).

Generated 2026-09-23 against the live cluster.

## Bearer token

**Not shared here, and it will not be committed to this repo.** `/v1/scans`
runs uncapped LLM inference billed to the operator, this fork is public, and a
value in git history is world-readable forever. Publishing it would hand any
reader the ability to spend against the endpoint.

Get it operator-brokered instead: the token lives on the host and the operator
(`ameanasad`) can `cfleet send` it to the UI worker's inbox. It is 43 chars and
is also held in the cluster's CDS secret store at `/codex-security/api-token`,
which is how the workload itself receives it — so the value need never travel in
a manifest, a repo, or a chat transcript.

The console already treats the token correctly: it is entered at runtime, held
in the tab only, never stored, and sent **sealed inside the attested channel**
(see [Browser notes](#browser-notes)) rather than as a plain header — so even in
use it is not exposed to whatever terminates TLS in front of the cluster.

## Endpoint

```
https://15.204.104.35:30443
```

The serving certificate is CDS-issued and attestation-bound, **not WebPKI**, so
a browser will not trust it on sight. The real check is `c8s verify` / the
in-browser attestation, not the TLS chain. See [Browser notes](#browser-notes)
for what that means for `fetch()`.

## Pins (confirm these against `ui/src/lib/config.ts`)

Read from the node image's published `manifest.json`; RTMR[1]/[2] re-verified
against a live quote from the endpoint today.

```
MRTD     9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1
RTMR[1]  3b260925fec6a0553b9a6aecf223a6ed1ddcbbee17df0b0e5c8bc056b0751c8530a83e71ed5b7ef9ff142ae842cdcecd
RTMR[2]  eb120e4c57137f7a3f72c6ca3403d6f26da427df4ddcf0ed2580b72ab08a7a6078034c728a78e1153f77f199c9bbf615
RTMR[3]  07a0d2e02325cf18ba3053bb5998447601b42b7745deef206cb3355d9e7bf1acea9ce71131d9991b734640bf8af7f75b
```

- **MRTD** is the TDVF firmware measurement only. On TDX it does **not** pin the
  guest — it is identical across different node images. Never present MRTD alone
  as "the measurement" on a trust page; the guest is pinned by RTMR[1]+[2].
- **RTMR[1]** the guest kernel; **RTMR[2]** the kernel command line, which
  carries the dm-verity root hash (so it pins the whole rootfs).
- **RTMR[3]** carries the operator launch-key binding, read live from the quote
  and included here for completeness. The UI does **not** pin it: it changes per
  launch, and the mesh CA below is the specific-cluster anchor instead. If you
  ever want the page to also pin the operator identity, `c8s-verify` accepts
  `expectedRtmr3`.

### Mesh CA (specific-cluster anchor)

Pinned out of band from an operator session that had already attested the node,
not from an unverified fetch. This is what makes a verdict specific-cluster
rather than "some genuine TDX machine".

```
-----BEGIN CERTIFICATE-----
MIIBqTCCAS+gAwIBAgIQDwFa3rbWAX/Q9O+vT+Ci6TAKBggqhkjOPQQDAzAWMRQw
EgYDVQQDEwtjOHMgTWVzaCBDQTAeFw0yNjA5MjMwNDMwMTRaFw0yNzA5MjMwNDMw
MTRaMBYxFDASBgNVBAMTC2M4cyBNZXNoIENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEkKjY1skCZNhMSgN2DCmRW9lOSxG+0pQ6HNr09v9CqlgXm3YDvE9V8XssMLna
K8z53IHIwX3M4y9zJlEeiv/kEBsUoB95rfHytNgB+R5Mp8j2T5n6C36OmxDYmX6s
atXyo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUQUNZf7feLOUEdj4SbY95oULRD6QwCgYIKoZIzj0EAwMDaAAwZQIxALY/0wnH
W/OwswGZE1UZDnA0N0AwaLL+mxfrGXPUp+3oRq8YV6MafB8EuoxAPMwiggIwCrgj
TlKCWHwYJ1n3LKb38QwPtGGlUznyHCEP5oBnCeFuodtIdf4/V03chYz34o6A
-----END CERTIFICATE-----
```

These four values plus the mesh CA match `ui/src/lib/config.ts` on
`confidential/scan-ui` (profile `codex-tdx`) as of this writing.

## Image and release strings (for a trust page)

```
Workload image   ghcr.io/confidential-dot-ai/codex-security:scan-api
Registry digest  sha256:f67d4ae6b867c528503623af989c8943a8784df8aab9304a058f1e48b473e2ec
Cluster release  c8s v0.33.1 (ec67bd8 + #691)
```

- The **registry digest** is what the allowlist pins and what a trust page
  should display — it differs from any digest `docker` computes locally, so
  always show the GHCR one above.
- **Cluster release** long form, for a disclosure/tooltip: c8s `v0.33.1`
  (`ec67bd8`) plus the operator-scope guard fix (c8s#691), a Cilium postStart
  fix, and a deployment-baked router upstream — node image built 2026-09-23,
  locked profile, Intel TDX node-CVM, Kubernetes `v1.36.4+rke2r1`. Suggested
  short form on the page: `c8s v0.33.1 (ec67bd8 + #691)`.

## Browser notes

**The tab must accept the CDS cert first — still true.** `public_tls.mode` is
`cds` in `/v1/discovery`, so the serving cert is attestation-bound, not WebPKI.
A browser blocks `fetch()` to the origin until the user has opened it once and
accepted the interstitial. Design the error state accordingly: a failure before
acceptance is a *network* error that happens **before any attestation ran** —
report it as "can't reach the endpoint", never as a verification verdict.

**CORS** — measured against the live endpoint today with an `Origin` header:

| Route | Preflight (`OPTIONS`) | Notes |
|---|---|---|
| `/v1/discovery` | `204`, `Access-Control-Allow-Origin: *` | methods `GET, POST, OPTIONS`; allow-headers `Authorization, Content-Type, X-C8s-Session`; max-age 600 |
| `/.well-known/c8s/attest-pq` | `204`, same CORS headers | the attestation + tunnel path |
| `/v1/scans` (direct) | **`401`, no CORS headers at all** | direct browser calls can never work — even the preflight is refused |

The takeaway: the attestation and tunnel endpoints under `/.well-known/c8s/` and
`/v1/discovery` are fully browser-ready, and **all API traffic must ride the
attested channel** — `Session.fetch` posts sealed requests to the tunnel, which
is why `X-C8s-Session` is in the allow-headers list. Do **not** call `/v1/scans`
directly from the browser; it will fail on CORS regardless of the token.
`ui/src/lib/api.ts` already does this correctly (every call goes through
`Session.fetch`).

## API contract (spoken over the attested channel)

All bearer-gated; unauthenticated `/v1/scans*` returns `401`.

- `POST /v1/scans` `{repository, revision?}` — queue a scan; omit `revision` and
  the service resolves `HEAD`. Returns the job.
- `GET /v1/scans` — list jobs.
- `GET /v1/scans/:id` — job state, incl. per-repository `result`.
- `GET /v1/scans/:id/log` — the scan log (tail).
- `GET /v1/scans/:id/files` and `/v1/scans/:id/files/<path>` — artifacts
  (`report.md`, `findings.json`, SARIF).

Scans run serially and take ~60–120s. Treat
`result.status: completed_with_incomplete_coverage` as **completed-with-warning**,
not a failure — `outcomeOf()` in `ui/src/lib/api.ts` already encodes this.

Note: the upstream findings/dashboard routes (`/v1/findings`, `/v1/dashboard`,
`/dashboard`) are **unauthenticated** and expose stored findings — a gap to
close before real use, and worth not linking from a public console.

## How it is wired

```
internet ──▶ 15.204.104.35:30443
             NodePort front → the TDX node-CVM's c8s router (nginx + cds-attest)
                └─ attested PQ tunnel ──▶ codex-security serve, inside the CVM
```

The router→workload hop is a mesh-wrapped headless Service, so it is plaintext
HTTP inside the guest wrapped in the ratls mesh's attested mTLS. The router's
upstream is baked into the node image (on v0.33.1 it must be — the value renders
at image build time and the in-guest guard denies changing it afterwards).

The scan API's allowlist entry pins the image by the registry digest above,
`command`/`args` exactly, and grants read on the OpenAI key and the API token
secret paths — nothing else on the cluster can read them.
