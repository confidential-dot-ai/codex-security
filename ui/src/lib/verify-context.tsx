"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { Session } from "c8s-verify";
import {
  runVerification,
  VerificationError,
  type Measured,
  type StepId,
  type StepState,
  type VerifySuccess,
} from "./verify-flow";
import { MESH_CA_PEM, PINS, SITE, parseManifest } from "./config";

export interface StepInfo {
  state: StepState;
  detail?: string;
}

export type VerifyStatus = "idle" | "running" | "ok" | "fail";

export interface PinsState {
  mrtd: string;
  rtmr1: string;
  rtmr2: string;
  meshCaPem: string;
}

interface VerifyContextValue {
  endpoint: string;
  setEndpoint: (v: string) => void;
  status: VerifyStatus;
  steps: Record<StepId, StepInfo>;
  result: VerifySuccess | null;
  error: { code?: string; message: string; step: StepId } | null;
  measured: Measured | null;
  run: () => Promise<void>;
  /** Increments once per user-initiated verify, so scan state from an older
   *  channel can be discarded. Not bumped by reconnect(). */
  verifyEpoch: number;
  getSession: () => Session | null;
  reconnect: () => Promise<Session | null>;
  disconnect: () => void;
  pins: PinsState;
  setPin: (k: keyof PinsState, v: string) => void;
  pinsEditable: boolean;
  setPinsEditable: (v: boolean) => void;
  pinsEdited: boolean;
  resetPins: () => void;
  loadManifest: (text: string) => void;
  manifestNote: string | null;
  /** Bearer token for /v1/scans. Tab-only: never persisted anywhere. */
  token: string;
  setToken: (v: string) => void;
}

const INITIAL_STEPS: Record<StepId, StepInfo> = {
  nonce: { state: "idle" },
  dcap: { state: "idle" },
  mrtd: { state: "idle" },
  rtmr1: { state: "idle" },
  rtmr2: { state: "idle" },
  meshca: { state: "idle" },
  channel: { state: "idle" },
};

const PUBLISHED_PINS: PinsState = {
  mrtd: PINS.mrtd,
  rtmr1: PINS.rtmr1,
  rtmr2: PINS.rtmr2,
  meshCaPem: MESH_CA_PEM,
};

const VerifyContext = createContext<VerifyContextValue | null>(null);

export function VerifyProvider({ children }: { children: ReactNode }) {
  const [endpoint, setEndpoint] = useState<string>(SITE.defaultEndpoint);
  const [status, setStatus] = useState<VerifyStatus>("idle");
  const [steps, setSteps] = useState<Record<StepId, StepInfo>>(INITIAL_STEPS);
  const [result, setResult] = useState<VerifySuccess | null>(null);
  const [error, setError] = useState<VerifyContextValue["error"]>(null);
  const [pins, setPins] = useState<PinsState>(PUBLISHED_PINS);
  const [pinsEditable, setPinsEditable] = useState(false);
  const [manifestNote, setManifestNote] = useState<string | null>(null);
  const [verifyEpoch, setVerifyEpoch] = useState(0);
  const [token, setToken] = useState("");
  const sessionRef = useRef<Session | null>(null);

  const setStep = useCallback((id: StepId, state: StepState, detail?: string) => {
    setSteps((prev) => ({ ...prev, [id]: { state, detail: detail ?? prev[id].detail } }));
  }, []);

  const execute = useCallback(
    async (animate: boolean): Promise<VerifySuccess> => {
      const out = await runVerification(
        endpoint,
        { mrtd: pins.mrtd, rtmr1: pins.rtmr1, rtmr2: pins.rtmr2 },
        pins.meshCaPem,
        setStep,
        animate,
      );
      sessionRef.current = out.session;
      setResult(out);
      setStatus("ok");
      setError(null);
      return out;
    },
    [endpoint, pins, setStep],
  );

  const run = useCallback(async () => {
    setStatus("running");
    setSteps(INITIAL_STEPS);
    setError(null);
    // A fresh verify opens a new channel; anything tied to the old one is stale.
    setVerifyEpoch((n) => n + 1);
    try {
      await execute(true);
    } catch (e) {
      setStatus("fail");
      sessionRef.current = null;
      setResult(null);
      if (e instanceof VerificationError) {
        setError({ code: e.code, message: e.message, step: e.step });
      } else {
        setError({ message: e instanceof Error ? e.message : String(e), step: "nonce" });
      }
    }
  }, [execute]);

  const getSession = useCallback(() => sessionRef.current, []);

  /** Quiet re-verify (no cascade animation): replaces an expired idle session. */
  const reconnect = useCallback(async (): Promise<Session | null> => {
    try {
      const out = await execute(false);
      return out.session;
    } catch {
      sessionRef.current = null;
      setStatus("fail");
      return null;
    }
  }, [execute]);

  const disconnect = useCallback(() => {
    sessionRef.current = null;
    setResult(null);
    setStatus("idle");
    setSteps(INITIAL_STEPS);
    setError(null);
    setVerifyEpoch((n) => n + 1);
  }, []);

  const setPin = useCallback((k: keyof PinsState, v: string) => {
    setPins((prev) => ({ ...prev, [k]: v }));
  }, []);

  const resetPins = useCallback(() => {
    setPins(PUBLISHED_PINS);
    setManifestNote(null);
  }, []);

  /** Load MRTD/RTMR[1]/RTMR[2] from a pasted node-image manifest.json, the
   *  same file `c8s verify --image-manifest` reads. Nothing here is fetched
   *  from the endpoint under test. */
  const loadManifest = useCallback((text: string) => {
    setManifestNote(null);
    if (!text.trim()) return;
    try {
      const pin = parseManifest(text);
      setPins((prev) => ({ ...prev, mrtd: pin.mrtd, rtmr1: pin.rtmr1, rtmr2: pin.rtmr2 }));
      setManifestNote("Image pins loaded from the pasted manifest.");
    } catch (e) {
      setManifestNote(`Could not read that manifest: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, []);

  const pinsEdited =
    pins.mrtd !== PUBLISHED_PINS.mrtd ||
    pins.rtmr1 !== PUBLISHED_PINS.rtmr1 ||
    pins.rtmr2 !== PUBLISHED_PINS.rtmr2 ||
    pins.meshCaPem !== PUBLISHED_PINS.meshCaPem;

  const value = useMemo<VerifyContextValue>(
    () => ({
      endpoint,
      setEndpoint,
      status,
      steps,
      result,
      error,
      measured: result?.measured ?? null,
      run,
      verifyEpoch,
      getSession,
      reconnect,
      disconnect,
      pins,
      setPin,
      pinsEditable,
      setPinsEditable,
      pinsEdited,
      resetPins,
      loadManifest,
      manifestNote,
      token,
      setToken,
    }),
    [
      endpoint, status, steps, result, error, run, verifyEpoch, getSession, reconnect,
      disconnect, pins, setPin, pinsEditable, pinsEdited, resetPins, loadManifest,
      manifestNote, token,
    ],
  );

  return <VerifyContext.Provider value={value}>{children}</VerifyContext.Provider>;
}

export function useVerify(): VerifyContextValue {
  const ctx = useContext(VerifyContext);
  if (!ctx) throw new Error("useVerify must be used inside <VerifyProvider>");
  return ctx;
}
