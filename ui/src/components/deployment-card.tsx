import { DEPLOYMENT } from "@/lib/config";
import { Card } from "./section";
import { CopyButton } from "./copy-button";

const ROWS: { k: string; v: string; href: string; go: string; note: string }[] = [
  {
    k: "Workload image",
    v: DEPLOYMENT.image,
    href: DEPLOYMENT.imageUrl,
    go: "package on GHCR",
    note: "The scan API container. Public, so you can pull it and read exactly what runs.",
  },
  {
    k: "Registry digest",
    v: DEPLOYMENT.digest,
    href: `${DEPLOYMENT.imageUrl}`,
    go: "published versions",
    note: "What GHCR serves and what the cluster admission allowlist pins. A digest computed locally differs, so compare against this one.",
  },
  {
    k: "Node image",
    v: DEPLOYMENT.nodeImage,
    href: DEPLOYMENT.nodeImageUrl,
    go: "package on GHCR",
    note: "The measured guest image. Its published manifest.json is where the MRTD and RTMR pins above come from.",
  },
  {
    k: "Cluster release",
    v: DEPLOYMENT.release,
    href: DEPLOYMENT.releaseUrl,
    go: "release notes",
    note: DEPLOYMENT.releaseLong,
  },
  {
    k: "Kubernetes",
    v: DEPLOYMENT.kubernetes,
    href: DEPLOYMENT.kubernetesUrl,
    go: "release notes",
    note: "The distribution running inside the confidential node. The control plane sits outside the trust boundary by design.",
  },
];

/** What is running behind the endpoint. Published alongside the pins, not a
 *  substitute for them: only the measurements above decide pass or fail. */
export function DeploymentCard() {
  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold text-heading">What runs behind the endpoint</h2>
      <p className="mb-4 text-[0.88rem] leading-relaxed text-foreground">
        These describe the deployment and every one of them is public. They are not what the
        browser checks — the measurements above are — but they are how you go and read the thing
        that was measured.
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
            <dd className="mt-1 text-[0.78rem] leading-relaxed text-muted">
              {r.note}{" "}
              <a
                className="font-mono text-accent hover:underline"
                href={r.href}
                target="_blank"
                rel="noreferrer"
              >
                {r.go} ↗
              </a>
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
