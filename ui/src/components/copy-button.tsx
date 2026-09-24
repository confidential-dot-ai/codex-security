"use client";

import { useState } from "react";

export function CopyButton({ text, label = "copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard unavailable */
        }
      }}
      className="rounded-md border border-border px-2 py-0.5 font-mono text-[0.68rem] text-muted transition-colors hover:border-accent hover:text-accent"
    >
      {done ? "copied" : label}
    </button>
  );
}
