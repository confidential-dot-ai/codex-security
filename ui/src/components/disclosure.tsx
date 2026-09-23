"use client";

import { useState } from "react";

/**
 * Collapsible block for long payloads (raw JSON, manifests). Expands inside
 * its parent card at card width, never full-bleed.
 */
export function Disclosure({
  summary,
  meta,
  children,
  defaultOpen = false,
}: {
  summary: string;
  meta?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-border bg-card">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <span
          className={`shrink-0 text-muted transition-transform inline-block ${open ? "rotate-90" : ""}`}
          aria-hidden
        >
          ▸
        </span>
        <span className="font-mono text-[0.8rem] text-foreground">{summary}</span>
        {meta && <span className="ml-auto font-mono text-[0.68rem] text-muted">{meta}</span>}
      </button>
      {open && <div className="border-t border-border px-4 py-3">{children}</div>}
    </div>
  );
}
