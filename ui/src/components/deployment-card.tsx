import { DEPLOYMENT } from "@/lib/config";
import { Card } from "./section";
import { CopyButton } from "./copy-button";

const ROWS: { k: string; v: string; href: string; note: string }[] = [
  {
    k: "Scan API image",
    v: `${DEPLOYMENT.image}@${DEPLOYMENT.digest}`,
    href: DEPLOYMENT.imageUrl,
    note: "The workload you are talking to, by the digest GHCR serves. This is the digest the cluster's admission allowlist pins, and it differs from one computed locally — so compare against this one.",
  },
  {
    k: "Cluster release",
    v: DEPLOYMENT.release,
    href: DEPLOYMENT.releaseUrl,
    note: "The c8s release the cluster runs. Public TLS is terminated by the router's in-guest ACME sidecar, so the serving key stays inside the enclave.",
  },
];

/** What runs behind the endpoint, by digest. Published alongside the pins, not
 *  a substitute for them: only the measurements above decide pass or fail. */
export function DeploymentCard() {
  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">What runs behind the endpoint</h2>
      <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
        Everything here is named by digest and everything here is public. These are not what the
        browser checks — the measurements above are — but they are how you go and read the thing
        that was measured.
      </p>
      <dl className="flex flex-col gap-3">
        {ROWS.map((r) => (
          <div key={r.k} className="border-t border-border pt-3 first:border-0 first:pt-0">
            <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">{r.k}</dt>
            <dd className="mt-0.5 flex items-start gap-2">
              <a
                className="min-w-0 break-all font-mono text-[0.78rem] text-accent hover:underline"
                href={r.href}
                target="_blank"
                rel="noreferrer"
              >
                {r.v}
              </a>
              <span className="code-block shrink-0 opacity-100">
                <CopyButton text={r.v} />
              </span>
            </dd>
            <dd className="mt-1 text-[0.78rem] leading-relaxed text-muted">{r.note}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
