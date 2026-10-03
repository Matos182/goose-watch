// triage packs 2 and 3: analysis in hops, each narrower than v1's single broad question.
//
//   hop 0 (code)  measure facts exactly: silence before, PDU timestamp age, sqNum at 0,
//                 stNum near 1, flags, baseline membership. Facts are never asked of a model.
//   hop 1 (model) for alerts whose cause is genuinely ambiguous, a System One Choice between
//                 evidence PATTERNS written in IEC 61850 terms (replay, restart, test set...).
//   hop 2 (code)  map the pattern distribution to a cause distribution. The mapping is domain
//                 knowledge, not a guess: a replay is an attack, a reboot is a device fault.
//
// Alerts whose class already fixes the pattern skip hop 1 and use v1's cause question.
// The rule's severity is untouched in every path.

import type { Alert } from "./rules";
import { buildState, CAUSES, distribution, prob, QUESTIONS, validate, type Cause, type SystemOneAdapter, type TriageResult } from "./triage";
import { safeText } from "./rules";

export const PACK2_VERSION = "triage-pack-2";

export const PATTERNS = {
  replay: "An earlier message re-sent by someone: the message's own timestamp is old, it arrives with no silence before it, and its sequence number is mid-sequence, not zero.",
  restart: "The publishing relay rebooted: the stream was silent first, then resumes with a state number near 1, a sequence number of 0 and a fresh timestamp.",
  test_equipment: "A test set or simulator on the bus: the test flag or the simulation bit is set.",
  impersonation: "A device that is not in the learned baseline, or a known control block sent from an unexpected MAC address, with no test flag or simulation bit.",
  other: "None of the patterns above fits the facts.",
} as const;
export type Pattern = keyof typeof PATTERNS;

export const PATTERN_TO_CAUSE: Record<Pattern, Cause> = {
  replay: "cyberattack", impersonation: "cyberattack", restart: "device_fault", test_equipment: "maintenance", other: "unclear",
};

/** Classes whose cause depends on the evidence pattern, not on the class alone. */
export const PATTERN_CLASSES = new Set(["STNUM_REGRESSION", "NEW_PUBLISHER", "SQNUM_RESET"]);

const STALE_MS = 5_000;

export function facts(a: Alert) {
  const c = a.context;
  // The learned TAL first (rules time silence against it too); 2000 ms only for alerts recorded without one.
  const tal = c.timeAllowedToLive ?? (typeof a.detail.timeAllowedToLive === "number" ? a.detail.timeAllowedToLive : 2000);
  return {
    alert: a.cls,
    publisher_in_learned_baseline: c.publisherInBaseline,
    source_mac_matches_baseline: c.macMatchesBaseline,
    test_flag_set: c.testFlag,
    simulation_bit_set: c.simulationBit,
    stream_was_silent_before_this_message: c.silenceBeforeMs !== undefined ? c.silenceBeforeMs > tal : "unknown",
    message_timestamp_is_older_than_5_seconds: c.pduTimestampAgeMs !== undefined ? c.pduTimestampAgeMs > STALE_MS : "unknown",
    sequence_number_is_zero: c.sqNum === 0,
    state_number_is_near_1: c.stNum !== undefined ? c.stNum <= 2 : "unknown",
    signal_lost_alert_just_before: c.otherAlertsLast60s.includes("TTL_EXPIRY"),
    control_block: safeText(a.gocbRef, 80),
  };
}

const PATTERN_QUESTION = {
  pattern: {
    type: "choice",
    instructions: "An IEC 61850 GOOSE monitor in a substation raised the alert in the state. The state lists measured facts. Which evidence pattern do these facts match?",
    criteria: PATTERNS,
  },
  needs_human: { type: "noul", instructions: "A human must check this alert before the substation can be considered safe." },
} as const;

function fromPatterns(raw: any, model: string) {
  const ans = raw?.answers;
  if (!ans) throw new Error("no answers");
  const pat = distribution(ans.pattern?.probabilities, Object.keys(PATTERNS)) as Record<Pattern, number>;
  const needsHuman = prob(ans.needs_human?.noul);
  const cause = Object.fromEntries(Object.keys(CAUSES).map((k) => [k, 0])) as Record<Cause, number>;
  for (const [p, v] of Object.entries(pat) as [Pattern, number][]) cause[PATTERN_TO_CAUSE[p]] += v;
  const [causeWinner, causeP] = (Object.entries(cause) as [Cause, number][]).reduce((x, y) => (y[1] > x[1] ? y : x));
  return { model, pack: PACK2_VERSION, cause, causeWinner, causeP, urgency: [0, 0, 0] as [number, number, number], needsHuman, patterns: pat };
}

export async function triage2(ad: SystemOneAdapter, a: Alert): Promise<TriageResult> {
  if (PATTERN_CLASSES.has(a.cls)) return ad.ask(facts(a), PATTERN_QUESTION, (raw) => fromPatterns(raw, ad.model));
  return ad.ask(facts(a), QUESTIONS, (raw) => ({ ...validate(raw, ad.model), pack: PACK2_VERSION }));
}

// triage-pack-3: pack 2, except that classes without a pattern hop get the facts AND v1's state
// (which carries the rule's meaning). Found live: without the rule meaning, Nimble read a forged
// status (DATA_WITHOUT_STNUM) as a device fault at 0.81.
export const PACK3_VERSION = "triage-pack-3";

export async function triage3(ad: SystemOneAdapter, a: Alert): Promise<TriageResult> {
  if (PATTERN_CLASSES.has(a.cls)) {
    const r = await ad.ask(facts(a), PATTERN_QUESTION, (raw) => fromPatterns(raw, ad.model));
    return r.ok ? { ok: true, triage: { ...r.triage, pack: PACK3_VERSION } } : r;
  }
  return ad.ask({ ...buildState(a, a.context), ...facts(a) }, QUESTIONS, (raw) => ({ ...validate(raw, ad.model), pack: PACK3_VERSION }));
}
