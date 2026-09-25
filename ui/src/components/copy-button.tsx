"use client";

import { useState } from "react";

/**
 * Two placements, one behaviour. `floating` pins the button to the top-right of
 * a `.code-block` and fades in on hover, per globals.css; `inline` is a small
 * chip that sits in a row of text. Everything that copies on this site uses
 * one of the two, so the affordance is always in the same place.
 */
export function CopyButton({
  text,
  label = "copy",
  variant = "inline",
}: {
  text: string;
  label?: string;
  variant?: "inline" | "floating";
}) {
  const [done, setDone] = useState(false);
  const inline =
    "rounded-md border border-border px-2 py-0.5 font-mono text-[0.68rem] text-muted transition-colors hover:border-accent hover:text-accent";
  return (
    <button
      type="button"
      aria-label={done ? "copied" : "copy to clipboard"}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard unavailable */
        }
      }}
      className={variant === "floating" ? "copy-button" : inline}
    >
      {done ? "copied" : label}
    </button>
  );
}
