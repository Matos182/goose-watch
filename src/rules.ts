// Deterministic rules: the safety floor. The model may explain an alert,
// never raise or clear one.

import type { GooseEvent } from "./decode";
import type { AlertContext } from "./triage";

export type AlertClass =
  | "NEW_PUBLISHER" | "CONFIG_CHANGE" | "STNUM_REGRESSION" | "STNUM_JUMP" | "SQNUM_RESET"
  | "DATA_WITHOUT_STNUM" | "TTL_EXPIRY" | "TEST_MODE" | "SIM_BIT" | "MALFORMED_PDU";

export type Severity = 1 | 2 | 3; // 1 note · 2 investigate · 3 act now

export const RULE_SEVERITY: Record<AlertClass, Severity> = {
  NEW_PUBLISHER: 3, STNUM_REGRESSION: 3, DATA_WITHOUT_STNUM: 3, TTL_EXPIRY: 3,
  STNUM_JUMP: 2, SQNUM_RESET: 2, CONFIG_CHANGE: 2, MALFORMED_PDU: 2,
  TEST_MODE: 1, SIM_BIT: 1,
};

export const RULE_TEXT: Record<AlertClass, string> = {
  NEW_PUBLISHER: "A GOOSE publisher not in the learned baseline (unknown control block or unexpected MAC address).",
  CONFIG_CHANGE: "The dataset or configuration revision differs from the learned baseline.",
  STNUM_REGRESSION: "The state number went backwards: an old message was replayed or the device restarted.",
  STNUM_JUMP: "The state number skipped ahead by more than one: lost events or an injected message.",
  SQNUM_RESET: "The sequence number fell back without a new state: a restart or a forged message.",
  DATA_WITHOUT_STNUM: "The published values changed without a new state number: a forged status is likely.",
  TTL_EXPIRY: "No message arrived within the publisher's time-allowed-to-live: the signal is lost.",
  TEST_MODE: "The publisher marked its messages as test: maintenance or a forged test flag.",
  SIM_BIT: "The Ed2 simulation bit is set: these messages come from a test set or simulator.",
  MALFORMED_PDU: "A header field (state number, sequence number, time-allowed-to-live or revision) is missing or invalid: a broken device or a crafted frame. The frame was not used.",
};

export interface BaselineEntry {
  key: string;
  srcMac: string;
  datSet: string;
  confRev: number;
  numDatSetEntries: number;
}

export interface Baseline {
  version: 1;
  publishers: BaselineEntry[];
}

export interface Alert {
  cls: AlertClass;
  severity: Severity;
  key: string;
  srcMac: string;
  gocbRef: string;
  tMs: number;
  detail: Record<string, number | string | boolean>;
  count: number; // occurrences folded into this alert
  lastMs: number; // last occurrence; a condition that keeps recurring stays one alert
  context: AlertContext; // evidence snapshot handed to the model
}

export const streamKey = (e: Pick<GooseEvent, "appId" | "gocbRef">) => `${e.appId.toString(16).padStart(4, "0")}|${e.gocbRef}`;

export function learn(events: Iterable<GooseEvent>): Baseline {
  const m = new Map<string, BaselineEntry>();
  for (const e of events) {
    const key = streamKey(e);
    if (!m.has(key)) m.set(key, { key, srcMac: e.srcMac, datSet: e.datSet, confRev: e.confRev, numDatSetEntries: e.numDatSetEntries });
  }
  return { version: 1, publishers: [...m.values()].sort((a, b) => a.key.localeCompare(b.key)) };
}

interface Sequence {
  stNum: number;
  sqNum: number;
  values: string;
}

interface StreamState extends Sequence {
  lastSeen: number;
  tal: number;
  expired: boolean;
  // A lower sequence seen after a regression. It is adopted only once it has run on its own,
  // so a real relay restart re-arms the rules while a replay next to a live publisher never does.
  restart?: Sequence & { frames: number; since: number };
}

const DEDUPE_MS = 10_000;
// A restarted sequence is adopted after this many consistent frames and two time-allowed-to-live
// windows with no frame from the old sequence: a publisher that is still alive would have shown up.
const RESTART_FRAMES = 3;
const RESTART_TAL_WINDOWS = 2;
// Bounds for a flood of forged publishers: memory and alerts stay finite whatever arrives.
export const MAX_UNKNOWN_STREAMS = 256;
export const MAX_ALERTS = 10_000;
export const UNKNOWN_OVERFLOW_KEY = "ffff|*unknown-publisher-overflow*";

const U32 = 0xffff_ffff;
const isU32 = (n: number) => Number.isInteger(n) && n >= 0 && n <= U32;

/** Header fields the rules depend on. An invalid one must never reach the stream state (NaN compares false everywhere). */
export function invalidFields(e: GooseEvent): string[] {
  const bad: string[] = [];
  if (!Number.isFinite(e.tMs)) bad.push("time");
  if (!isU32(e.stNum)) bad.push("stNum");
  if (!isU32(e.sqNum)) bad.push("sqNum");
  if (!isU32(e.timeAllowedToLive) || e.timeAllowedToLive === 0) bad.push("timeAllowedToLive");
  if (!isU32(e.confRev)) bad.push("confRev");
  if (!isU32(e.numDatSetEntries)) bad.push("numDatSetEntries");
  if (!Number.isInteger(e.appId) || e.appId < 0 || e.appId > 0xffff) bad.push("appId");
  return bad;
}

export class RuleEngine {
  private known: Map<string, BaselineEntry>;
  private state = new Map<string, StreamState>();
  private open = new Map<string, Alert>();
  private unknown = new Set<string>();
  readonly alerts: Alert[] = [];

  constructor(baseline: Baseline, private onAlert: (a: Alert, isNew: boolean) => void = () => {}) {
    this.known = new Map(baseline.publishers.map((p) => [p.key, p]));
  }

  private ctx: Omit<AlertContext, "otherAlertsLast60s"> = { publisherInBaseline: false, macMatchesBaseline: false, testFlag: false, simulationBit: false };

  private raise(cls: AlertClass, e: Pick<GooseEvent, "tMs" | "srcMac" | "gocbRef" | "appId">, detail: Alert["detail"], key = streamKey(e)) {
    const id = `${cls}|${key}`;
    const prev = this.open.get(id);
    if (prev && e.tMs - prev.lastMs < DEDUPE_MS) {
      prev.count += 1;
      prev.lastMs = e.tMs;
      this.onAlert(prev, false);
      return;
    }
    const others = this.alerts.filter((x) => e.tMs - x.lastMs < 60_000).map((x) => x.cls);
    const context: AlertContext = { ...this.ctx, otherAlertsLast60s: [...new Set(others)] };
    const a: Alert = { cls, severity: RULE_SEVERITY[cls], key, srcMac: e.srcMac, gocbRef: e.gocbRef, tMs: e.tMs, detail, count: 1, lastMs: e.tMs, context };
    this.open.set(id, a);
    this.alerts.push(a);
    if (this.alerts.length > MAX_ALERTS) this.alerts.splice(0, this.alerts.length - MAX_ALERTS);
    this.onAlert(a, true);
  }

  /** Check every stream for silence up to `now`. Call on each event and on a timer when live. */
  tick(now: number) {
    for (const [key, s] of this.state) {
      // Silence only matters for publishers we expect: a rogue device going quiet is not a lost signal.
      if (!s.expired && this.known.has(key) && now - s.lastSeen > s.tal) {
        s.expired = true;
        const [appHex, ...ref] = key.split("|");
        const known = this.known.get(key);
        this.ctx = { publisherInBaseline: !!known, macMatchesBaseline: true, testFlag: false, simulationBit: false, silenceBeforeMs: now - s.lastSeen };
        this.raise("TTL_EXPIRY", { tMs: now, srcMac: known?.srcMac ?? "", gocbRef: ref.join("|"), appId: parseInt(appHex!, 16) },
          { silentMs: now - s.lastSeen, timeAllowedToLive: s.tal });
      }
    }
  }

  ingest(e: GooseEvent) {
    const bad = invalidFields(e);
    if (bad.length) {
      if (!Number.isFinite(e.tMs)) return; // tshark always stamps frames; nothing to anchor an alert to otherwise
      this.tick(e.tMs);
      const known = this.known.get(streamKey(e));
      this.ctx = { publisherInBaseline: !!known, macMatchesBaseline: known?.srcMac === e.srcMac, testFlag: e.test, simulationBit: e.simulationBit };
      this.raise("MALFORMED_PDU", e, { fields: bad.join(",") }, known ? streamKey(e) : this.admitUnknown(streamKey(e)));
      return;
    }
    this.tick(e.tMs);
    const key = streamKey(e);
    const known = this.known.get(key);
    const prev = this.state.get(key);
    this.ctx = {
      publisherInBaseline: !!known,
      macMatchesBaseline: known?.srcMac === e.srcMac,
      testFlag: e.test,
      simulationBit: e.simulationBit,
      ...(prev && known?.srcMac === e.srcMac && { stNumDelta: e.stNum - prev.stNum, silenceBeforeMs: e.tMs - prev.lastSeen }),
      sqNum: e.sqNum,
      stNum: e.stNum,
      ...(e.pduTMs !== null && { pduTimestampAgeMs: e.tMs - e.pduTMs }),
      ...(known && { confRevChanged: known.confRev !== e.confRev }),
    };
    if (!known) {
      const alertKey = this.admitUnknown(key);
      this.raise("NEW_PUBLISHER", e, { expectedMac: "none", datSet: e.datSet }, alertKey);
      if (alertKey === UNKNOWN_OVERFLOW_KEY) return; // past the bound, every forged stream folds into one alert
    } else if (known.srcMac !== e.srcMac) {
      this.raise("NEW_PUBLISHER", e, { expectedMac: known.srcMac, datSet: e.datSet });
    } else if (known.confRev !== e.confRev || known.datSet !== e.datSet || known.numDatSetEntries !== e.numDatSetEntries) {
      this.raise("CONFIG_CHANGE", e, { confRev: e.confRev, expectedConfRev: known.confRev, datSet: e.datSet });
    }
    if (e.test) this.raise("TEST_MODE", e, {});
    if (e.simulationBit) this.raise("SIM_BIT", e, {});

    // Sequence state is tracked only for baseline publishers from their baseline MAC, so a
    // spoofer cannot corrupt the legitimate sequence, and forged publishers (already a
    // NEW_PUBLISHER) cannot grow the state without bound.
    if (!known || known.srcMac !== e.srcMac) return;
    const values = e.values.join(",");
    const s = this.state.get(key);
    if (!s) {
      this.state.set(key, { stNum: e.stNum, sqNum: e.sqNum, values, lastSeen: e.tMs, tal: e.timeAllowedToLive, expired: false });
      return;
    }
    let accept = true;
    if (e.stNum < s.stNum) {
      this.raise("STNUM_REGRESSION", e, { stNum: e.stNum, lastStNum: s.stNum });
      accept = false; // never let a replay rewind our view of the stream...
      this.followRestart(s, e, values); // ...until the lower sequence proves to be a restart
    } else if (e.stNum > s.stNum + 1) {
      this.raise("STNUM_JUMP", e, { stNum: e.stNum, lastStNum: s.stNum });
    } else if (e.stNum === s.stNum) {
      if (e.sqNum < s.sqNum) {
        this.raise("SQNUM_RESET", e, { sqNum: e.sqNum, lastSqNum: s.sqNum, stNum: e.stNum });
      }
      if (values !== s.values) {
        this.raise("DATA_WITHOUT_STNUM", e, { stNum: e.stNum, sqNum: e.sqNum });
        accept = false;
      }
    }
    s.lastSeen = e.tMs;
    s.tal = e.timeAllowedToLive;
    s.expired = false;
    if (e.stNum >= s.stNum) s.restart = undefined; // the old sequence is alive: the lower one was a replay
    if (accept) {
      s.stNum = e.stNum;
      s.sqNum = e.sqNum;
      s.values = values;
    }
  }

  /** Key for an unknown stream's alerts: its own while under the bound, one shared key past it. */
  private admitUnknown(key: string): string {
    if (this.unknown.has(key)) return key;
    if (this.unknown.size >= MAX_UNKNOWN_STREAMS) return UNKNOWN_OVERFLOW_KEY;
    this.unknown.add(key);
    return key;
  }

  /**
   * Follow a lower sequence after a regression. A relay restart is a fresh sequence that keeps going
   * (stNum steady with sqNum rising, or stNum + 1). The rules on it stay armed while it is followed:
   * a value change without a new stNum is still forged data.
   */
  private followRestart(s: StreamState, e: GooseEvent, values: string) {
    const r = s.restart;
    const continues = r && (e.stNum === r.stNum ? e.sqNum > r.sqNum : e.stNum === r.stNum + 1);
    if (!r || !continues) {
      s.restart = { stNum: e.stNum, sqNum: e.sqNum, values, frames: 1, since: e.tMs };
      return;
    }
    if (e.stNum === r.stNum && values !== r.values) {
      this.raise("DATA_WITHOUT_STNUM", e, { stNum: e.stNum, sqNum: e.sqNum });
      return; // a forged value never advances the restarted sequence
    }
    r.stNum = e.stNum;
    r.sqNum = e.sqNum;
    r.values = values;
    r.frames += 1;
    if (r.frames >= RESTART_FRAMES && e.tMs - r.since >= RESTART_TAL_WINDOWS * e.timeAllowedToLive) {
      s.stNum = r.stNum;
      s.sqNum = r.sqNum;
      s.values = r.values;
      s.restart = undefined;
    }
  }
}

// Strip what could act on a terminal or flip text direction before display.
export function safeText(s: string, max = 120): string {
  const cleaned = s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, "�");
  return cleaned.length > max ? cleaned.slice(0, max - 1) + "…" : cleaned;
}
