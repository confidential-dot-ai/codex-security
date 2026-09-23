"use client";

import { STEPS, type StepId, type StepState } from "@/lib/attest";

const TONE: Record<StepState, { mark: string; color: string }> = {
  idle: { mark: "○", color: "var(--muted)" },
  active: { mark: "◐", color: "var(--accent)" },
  pass: { mark: "●", color: "var(--good)" },
  fail: { mark: "✕", color: "var(--bad)" },
  skip: { mark: "–", color: "var(--muted)" },
};

export function Cascade({
  states,
  failure,
}: {
  states: Record<StepId, StepState>;
  failure?: { step: StepId; message: string } | null;
}) {
  return (
    <ol className="space-y-2.5">
      {STEPS.map((step) => {
        const state = states[step.id] ?? "idle";
        const tone = TONE[state];
        return (
          <li key={step.id} className="flex gap-3">
            <span
              className={`mono mt-0.5 text-sm ${state === "active" ? "pulsing" : ""}`}
              style={{ color: tone.color }}
              aria-hidden
            >
              {tone.mark}
            </span>
            <div className="min-w-0">
              <div
                className="text-sm"
                style={{ color: state === "idle" ? "var(--muted)" : "var(--ink)" }}
              >
                {step.label}
              </div>
              <div className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
                {step.detail}
              </div>
              {failure && failure.step === step.id && (
                <div
                  className="mono text-xs mt-1.5 break-words"
                  style={{ color: "var(--bad)" }}
                >
                  {failure.message}
                </div>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
