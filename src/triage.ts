// Local System One triage over Ollama's /v1/systemone endpoint.
// The model explains and grades doubt; it never raises, clears or re-grades an alert.

import type { Alert } from "./rules";
import { RULE_TEXT, safeText } from "./rules";

export const CAUSES = {
  cyberattack: "Deliberate traffic from an unauthorised party: a forged, replayed, injected or impersonated GOOSE message.",
  maintenance: "Planned engineering work: test mode, simulation, a test set, or a configuration change being commissioned.",
  device_fault: "Equipment trouble with no one acting: a relay restart, a lost link, a failing device or network path.",
  unclear: "The evidence given does not support any one of the other causes over the rest.",
} as const;
export type Cause = keyof typeof CAUSES;

export const QUESTIONS = {
  cause: {
    type: "choice",
    instructions: "An IEC 61850 GOOSE monitor in an electrical substation raised the alert described in the state. What most likely caused it?",
    criteria: CAUSES,
  },
  urgency: {
    type: "score",
    instructions: "How soon should a protection engineer look at this alert?",
    criteria: ["Review at the next routine check", "Look at it today", "Look at it now, protection may be affected"],
  },
  needs_human: {
    type: "noul",
    instructions: "A human must check this alert before the substation can be considered safe.",
  },
} as const;

export const PACK_VERSION = "triage-pack-1";

export interface AlertContext {
  publisherInBaseline: boolean;
  macMatchesBaseline: boolean;
  testFlag: boolean;
  simulationBit: boolean;
  stNumDelta?: number; // new - last accepted
  stNum?: number; // the message's own state number
  sqNum?: number;
  pduTimestampAgeMs?: number; // frame arrival - PDU t
  silenceBeforeMs?: number; // gap since the stream's previous frame
  confRevChanged?: boolean;
  otherAlertsLast60s: string[];
}

export function buildState(a: Alert, ctx: AlertContext) {
  return {
    alert: a.cls,
    rule_meaning: RULE_TEXT[a.cls],
    control_block: safeText(a.gocbRef, 80),
    publisher_in_learned_baseline: ctx.publisherInBaseline,
    source_mac_matches_baseline: ctx.macMatchesBaseline,
    test_flag_set: ctx.testFlag,
    simulation_bit_set: ctx.simulationBit,
    ...(ctx.stNumDelta !== undefined && { state_number_change: ctx.stNumDelta }),
    ...(ctx.sqNum !== undefined && { sequence_number: ctx.sqNum }),
    ...(ctx.pduTimestampAgeMs !== undefined && { message_timestamp_age_seconds: Math.round(ctx.pduTimestampAgeMs / 1000) }),
    ...(ctx.silenceBeforeMs !== undefined && { silence_before_seconds: Math.round(ctx.silenceBeforeMs / 100) / 10 }),
    ...(ctx.confRevChanged !== undefined && { configuration_revision_changed: ctx.confRevChanged }),
    other_alerts_last_minute: ctx.otherAlertsLast60s,
  };
}

export interface Triage {
  model: string;
  pack: string;
  cause: Record<Cause, number>;
  causeWinner: Cause;
  causeP: number;
  urgency: [number, number, number];
  needsHuman: number;
  latencyMs: number;
}

export type TriageResult = { ok: true; triage: Triage } | { ok: false; failure: "transport" | "timeout" | "http" | "invalid_answer"; detail: string };

const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):\d+$/;

export class SystemOneAdapter {
  constructor(readonly base: string, readonly model: string, readonly timeoutMs = 15_000) {
    if (!LOOPBACK.test(base)) throw new Error("only a loopback System One endpoint is allowed (no capture data leaves the machine)");
  }

  async triage(a: Alert, ctx: AlertContext): Promise<TriageResult> {
    return this.ask(buildState(a, ctx), QUESTIONS, (raw) => validate(raw, this.model));
  }

  /** One System One request with any question set; `check` turns the raw answer into a Triage or throws. */
  async ask(state: object, questions: object, check: (raw: any) => Omit<Triage, "latencyMs">): Promise<TriageResult> {
    const t0 = performance.now();
    let res: Response;
    try {
      res = await fetch(`${this.base}/v1/systemone`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: this.model, state, questions }),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      const name = (e as Error).name;
      return { ok: false, failure: name === "TimeoutError" ? "timeout" : "transport", detail: name };
    }
    if (!res.ok) return { ok: false, failure: "http", detail: String(res.status) };
    const body = await res.text();
    if (body.length > 64_000) return { ok: false, failure: "invalid_answer", detail: "oversized" };
    try {
      return { ok: true, triage: { ...check(JSON.parse(body)), latencyMs: performance.now() - t0 } };
    } catch (e) {
      return { ok: false, failure: "invalid_answer", detail: (e as Error).message };
    }
  }
}

export const prob = (x: unknown): number => {
  if (typeof x !== "number" || !Number.isFinite(x) || x < 0 || x > 1) throw new Error("probability out of range");
  return x;
};

export function distribution(raw: unknown, keys: readonly string[]): Record<string, number> {
  if (typeof raw !== "object" || raw === null) throw new Error("missing probabilities");
  const r = raw as Record<string, unknown>;
  if (Object.keys(r).length !== keys.length || !keys.every((k) => k in r)) throw new Error("probability keys differ from criteria");
  const out = Object.fromEntries(keys.map((k) => [k, prob(r[k])]));
  const sum = Object.values(out).reduce((s, v) => s + v, 0);
  if (Math.abs(sum - 1) > 0.02) throw new Error("probabilities do not sum to 1");
  return out;
}

// We never trust the supplier's `choice`, `score`, `confidence` or `legend`:
// the winner is recomputed from the distribution.
export function validate(raw: any, model: string): Omit<Triage, "latencyMs"> {
  const ans = raw?.answers;
  if (!ans) throw new Error("no answers");
  const cause = distribution(ans.cause?.probabilities, Object.keys(CAUSES)) as Record<Cause, number>;
  const urg = distribution(ans.urgency?.probabilities, ["0", "1", "2"]);
  const needsHuman = prob(ans.needs_human?.noul);
  const [causeWinner, causeP] = (Object.entries(cause) as [Cause, number][]).reduce((a, b) => (b[1] > a[1] ? b : a));
  return { model, pack: PACK_VERSION, cause, causeWinner, causeP, urgency: [urg["0"]!, urg["1"]!, urg["2"]!], needsHuman };
}

/** The verdict shown to people. Severity is ALWAYS the rule's; the model only adds its reading. */
export function verdict(a: Alert, t: TriageResult, gate: number) {
  if (!t.ok) return { severity: a.severity, ai: `AI unavailable (${t.failure})`, notSure: true as const };
  const tr = t.triage;
  const notSure = tr.causeP < gate || tr.causeWinner === "unclear";
  return {
    severity: a.severity,
    ai: notSure
      ? `AI not sure (best guess ${tr.causeWinner} ${tr.causeP.toFixed(2)}): a human decides`
      : `AI reading: ${tr.causeWinner} ${tr.causeP.toFixed(2)} · needs a human ${tr.needsHuman.toFixed(2)}`,
    notSure,
  };
}
