import { DEPLOYMENT, SITE } from "@/lib/config";
import { Card } from "./section";
import { CopyButton } from "./copy-button";

const ROWS: { k: string; v: string; note: string }[] = [
  {
    k: "Endpoint",
    v: SITE.defaultEndpoint,
    note: "The c8s router in front of the scan API. Its certificate is CDS-issued and attestation-bound, not WebPKI.",
  },
  {
    k: "Workload image",
    v: DEPLOYMENT.image,
    note: "The scan API container. Public, so you can pull and read it.",
  },
  {
    k: "Registry digest",
    v: DEPLOYMENT.digest,
    note: "What GHCR serves and what the cluster admission allowlist pins. It differs from a digest computed locally, so this is the one to compare.",
  },
  {
    k: "Cluster release",
    v: DEPLOYMENT.release,
    note: DEPLOYMENT.releaseLong,
  },
];

/** What is running behind the endpoint. Published alongside the pins, not a
 *  substitute for them: only the measurements above decide pass or fail. */
export function DeploymentCard() {
  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">What is running behind it</h2>
      <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
        These strings describe the deployment. They are not what the browser checks — the
        measurements above are — but they tell you which public image to go and read.
      </p>
      <dl className="flex flex-col gap-3">
        {ROWS.map((r) => (
          <div key={r.k} className="border-t border-border pt-3 first:border-0 first:pt-0">
            <dt className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">{r.k}</dt>
            <dd className="mt-0.5 flex items-start gap-2">
              <span className="min-w-0 break-all font-mono text-[0.78rem] text-foreground">
                {r.v}
              </span>
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
