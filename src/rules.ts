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
  // The largest time-allowed-to-live seen while learning. TAL is a field in every frame, so an
  // attacker can set it; the rules time silence against this learned value, never a frame's.
  timeAllowedToLive?: number;
  // Where the publisher sends: a frame for another multicast address or VLAN is a configuration change.
  dstMac?: string;
  vlanId?: number | null;
  // Dataset member names from an SCD (`learn --scd`), in allData order. Display only: no rule reads them.
  members?: string[];
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
    const p = m.get(key);
    if (!p) m.set(key, { key, srcMac: e.srcMac, datSet: e.datSet, confRev: e.confRev, numDatSetEntries: e.numDatSetEntries, timeAllowedToLive: e.timeAllowedToLive, dstMac: e.dstMac, vlanId: e.vlanId });
    else p.timeAllowedToLive = Math.max(p.timeAllowedToLive ?? 0, e.timeAllowedToLive);
  }
  return { version: 1, publishers: [...m.values()].sort((a, b) => a.key.localeCompare(b.key)) };
}

interface Sequence {
  stNum: number;
  sqNum: number;
  values: string;
}

/** A stream's anchor is the sequence the rules trust; its fields are the anchor's. */
interface StreamState extends Sequence {
  lastSeen: number; // any frame on the stream (for TTL)
  anchorSeen: number; // the last frame that continued the anchor
  talSeen: number; // largest TAL on the anchor's own frames: the fallback when the baseline has none
  expired: boolean;
  announcedMs?: number; // when the current silence was last announced
  // A lower sequence after a regression. Every sequence rule runs on it from its first frame, so
  // nothing goes unwatched while it is followed. It replaces the anchor only with restart evidence.
  shadow?: Sequence & { frames: number; since: number; restartEvidence: boolean };
}

// A repeat within DEDUPE_MS of the last occurrence folds into the open alert, but an alert never
// absorbs repeats for longer than REALERT_MS: a condition that keeps going is re-announced once a
// minute, so a noisy first event cannot hide the ones after it downstream.
const DEDUPE_MS = 10_000;
export const REALERT_MS = 60_000;
// Restart evidence, fixed when the lower sequence starts: the anchor was silent for longer than its
// trusted time-allowed-to-live (a rebooting relay goes quiet), and the new message's own timestamp
// is fresh (GOOSE t is the time of the last state change, and a reboot is one; a replay carries the
// old one). Without both, the lower sequence is never adopted and its STNUM_REGRESSION keeps
// recurring: an extra alert, never a silence.
const FRESH_MS = 5_000;
const FUTURE_SKEW_MS = 1_000; // a timestamp from the future is fresh only within this much clock skew
// With evidence, the lower sequence is adopted after this many strictly advancing frames, over at
// least two trusted TAL windows and RESTART_MIN_MS of wall clock, with no frame from the anchor: a
// publisher that is still alive would have shown up. Nothing in a frame can shorten this.
const RESTART_FRAMES = 3;
const RESTART_TAL_WINDOWS = 2;
const RESTART_MIN_MS = 10_000;
// Bounds for a flood of forged publishers: memory and alerts stay finite whatever arrives. An
// unknown stream idle for UNKNOWN_IDLE_MS gives its slot back, so a later rogue still gets its own alert.
export const MAX_UNKNOWN_STREAMS = 256;
export const UNKNOWN_IDLE_MS = 60_000;
// A baseline publisher silent since start-up is reported after its learned TAL, but never in the
// first START_GRACE_MS (capture may start mid-heartbeat); ABSENT_DEFAULT_MS when the baseline has no TAL.
const START_GRACE_MS = 10_000;
const ABSENT_DEFAULT_MS = 60_000;
export const MAX_ALERTS = 10_000;
const MAX_OPEN = 1_024;
export const UNKNOWN_OVERFLOW_KEY = "ffff|*unknown-publisher-overflow*";

const U32 = 0xffff_ffff;
const isU32 = (n: number) => Number.isInteger(n) && n >= 0 && n <= U32;

/** Header fields the rules depend on. An invalid one must never reach the stream state (NaN compares false everywhere). */
export function invalidFields(e: GooseEvent): string[] {
  const bad: string[] = [];
  if (!Number.isFinite(e.tMs)) bad.push("time");
  if (!e.gocbRef) bad.push("gocbRef");
  if (!isU32(e.stNum)) bad.push("stNum");
  if (!isU32(e.sqNum)) bad.push("sqNum");
  if (!isU32(e.timeAllowedToLive) || e.timeAllowedToLive === 0) bad.push("timeAllowedToLive");
  // tshark types these two as signed 32-bit, so a large legitimate value can arrive negative; the
  // rules only compare them for equality, and NaN is what must never pass.
  if (!Number.isInteger(e.confRev)) bad.push("confRev");
  if (!Number.isInteger(e.numDatSetEntries)) bad.push("numDatSetEntries");
  if (!Number.isInteger(e.appId) || e.appId < 0 || e.appId > 0xffff) bad.push("appId");
  return bad;
}

export class RuleEngine {
  private known: Map<string, BaselineEntry>;
  private state = new Map<string, StreamState>();
  private open = new Map<string, Alert>();
  private unknown = new Map<string, number>(); // unknown stream key → last seen
  private startMs?: number; // first time the engine saw the clock
  private absent = new Map<string, number>(); // baseline publishers never seen → last announced
  readonly alerts: Alert[] = [];

  constructor(baseline: Baseline, private onAlert: (a: Alert, isNew: boolean) => void = () => {}) {
    this.known = new Map(baseline.publishers.map((p) => [p.key, p]));
  }

  private ctx: Omit<AlertContext, "otherAlertsLast60s"> = { publisherInBaseline: false, macMatchesBaseline: false, testFlag: false, simulationBit: false };

  private raise(cls: AlertClass, e: Pick<GooseEvent, "tMs" | "srcMac" | "gocbRef" | "appId">, detail: Alert["detail"], key = streamKey(e), fold = "") {
    // `fold` narrows what may fold together: a regression to a different stNum is a new event, never a repeat.
    const id = fold ? `${cls}|${key}|${fold}` : `${cls}|${key}`;
    const prev = this.open.get(id);
    if (prev && e.tMs - prev.lastMs < DEDUPE_MS && e.tMs - prev.tMs < REALERT_MS) {
      prev.count += 1;
      prev.lastMs = e.tMs;
      if (key === UNKNOWN_OVERFLOW_KEY) Object.assign(prev.detail, detail); // keep naming the latest offender
      this.onAlert(prev, false);
      return;
    }
    const others = this.alerts.filter((x) => e.tMs - x.lastMs < 60_000).map((x) => x.cls);
    const context: AlertContext = { ...this.ctx, otherAlertsLast60s: [...new Set(others)] };
    const a: Alert = { cls, severity: RULE_SEVERITY[cls], key, srcMac: e.srcMac, gocbRef: e.gocbRef, tMs: e.tMs, detail, count: 1, lastMs: e.tMs, context };
    this.open.set(id, a);
    // An open alert that has been quiet for DEDUPE_MS can never fold again, so it is safe to forget.
    if (this.open.size > MAX_OPEN) for (const [k, o] of this.open) if (e.tMs - o.lastMs >= DEDUPE_MS) this.open.delete(k);
    // Still over: drop the oldest. A dropped entry only means its next repeat starts a new alert.
    for (const k of this.open.keys()) { if (this.open.size <= MAX_OPEN) break; this.open.delete(k); }
    this.alerts.push(a);
    if (this.alerts.length > MAX_ALERTS) this.alerts.splice(0, this.alerts.length - MAX_ALERTS);
    this.onAlert(a, true);
  }

  /** Check every stream for silence up to `now`. Call on each event and on a timer when live. */
  tick(now: number) {
    for (const [key, s] of this.state) {
      // Silence only matters for publishers we expect: a rogue device going quiet is not a lost signal.
      const known = this.known.get(key);
      if (!known) continue;
      const tal = this.trustedTal(known, s);
      if (now - s.lastSeen > tal && (!s.expired || now - s.announcedMs! >= REALERT_MS)) {
        // A silence is announced when it starts and again each minute while it lasts.
        s.expired = true;
        s.announcedMs = now;
        const [appHex, ...ref] = key.split("|");
        this.ctx = { publisherInBaseline: true, macMatchesBaseline: true, testFlag: false, simulationBit: false, silenceBeforeMs: now - s.lastSeen };
        this.raise("TTL_EXPIRY", { tMs: now, srcMac: known.srcMac, gocbRef: ref.join("|"), appId: parseInt(appHex!, 16) },
          { silentMs: now - s.lastSeen, timeAllowedToLive: tal });
      }
    }
    // A baseline publisher that has not sent a single frame since the monitor started is a lost
    // signal too, once its learned TAL (or ABSENT_DEFAULT_MS without one) and a start-up grace are over.
    this.startMs ??= now;
    for (const [key, known] of this.known) {
      if (this.state.has(key)) continue;
      const wait = Math.max(known.timeAllowedToLive ?? ABSENT_DEFAULT_MS, START_GRACE_MS);
      if (now - this.startMs <= wait) continue;
      const announced = this.absent.get(key);
      if (announced !== undefined && now - announced < REALERT_MS) continue;
      this.absent.set(key, now);
      const [appHex, ...ref] = key.split("|");
      this.ctx = { publisherInBaseline: true, macMatchesBaseline: true, testFlag: false, simulationBit: false, silenceBeforeMs: now - this.startMs };
      this.raise("TTL_EXPIRY", { tMs: now, srcMac: known.srcMac, gocbRef: ref.join("|"), appId: parseInt(appHex!, 16) },
        { silentMs: now - this.startMs, timeAllowedToLive: known.timeAllowedToLive ?? ABSENT_DEFAULT_MS, neverSeen: true });
    }
  }

  ingest(e: GooseEvent) {
    if (!Number.isFinite(e.tMs)) return; // tshark always stamps frames; nothing to anchor an alert to otherwise
    this.tick(e.tMs);
    const key = streamKey(e);
    const known = this.known.get(key);
    const bad = invalidFields(e);
    const prev = this.state.get(key);
    this.ctx = bad.length
      ? { publisherInBaseline: !!known, macMatchesBaseline: known?.srcMac === e.srcMac, testFlag: e.test, simulationBit: e.simulationBit }
      : {
          publisherInBaseline: !!known,
          macMatchesBaseline: known?.srcMac === e.srcMac,
          testFlag: e.test,
          simulationBit: e.simulationBit,
          ...(known?.timeAllowedToLive !== undefined && { timeAllowedToLive: known.timeAllowedToLive }),
          ...(prev && known?.srcMac === e.srcMac && { stNumDelta: e.stNum - prev.stNum, silenceBeforeMs: e.tMs - prev.lastSeen }),
          sqNum: e.sqNum,
          stNum: e.stNum,
          ...(e.pduTMs !== null && { pduTimestampAgeMs: e.tMs - e.pduTMs }),
          ...(known && { confRevChanged: known.confRev !== e.confRev }),
        };

    // Who sent it comes first: a broken header must not hide a forged publisher.
    if (!known) {
      const alertKey = this.admitUnknown(key, e.tMs);
      const overflow = alertKey === UNKNOWN_OVERFLOW_KEY;
      this.raise("NEW_PUBLISHER", e, { expectedMac: "none", datSet: e.datSet,
        ...(overflow && { unknownStreams: this.unknown.size, latestGocbRef: safeText(e.gocbRef, 80), latestMac: e.srcMac }) }, alertKey);
      if (bad.length) this.raise("MALFORMED_PDU", e, { fields: bad.join(",") }, alertKey);
      if (overflow || bad.length) return; // past the bound, every forged stream folds into one alert
    } else if (known.srcMac !== e.srcMac) {
      this.raise("NEW_PUBLISHER", e, { expectedMac: known.srcMac, datSet: e.datSet });
    }
    if (bad.length) {
      this.raise("MALFORMED_PDU", e, { fields: bad.join(",") });
      return; // an invalid header never reaches the stream state
    }
    if (known && known.srcMac === e.srcMac && (known.confRev !== e.confRev || known.datSet !== e.datSet ||
        known.numDatSetEntries !== e.numDatSetEntries || e.timeAllowedToLive > (known.timeAllowedToLive ?? Infinity) ||
        (known.dstMac !== undefined && known.dstMac !== e.dstMac) || (known.vlanId !== undefined && known.vlanId !== e.vlanId) || e.ndsCom)) {
      this.raise("CONFIG_CHANGE", e, { confRev: e.confRev, expectedConfRev: known.confRev, datSet: e.datSet, timeAllowedToLive: e.timeAllowedToLive,
        dstMac: e.dstMac, vlanId: e.vlanId ?? "none", ndsCom: e.ndsCom });
    }
    if (e.test) this.raise("TEST_MODE", e, {});
    if (e.simulationBit) {
      this.raise("SIM_BIT", e, {});
      return; // a simulated frame is a test set talking: it never keeps the real publisher's sequence or signal alive
    }

    // Sequence state is tracked only for baseline publishers from their baseline MAC, so a
    // spoofer cannot corrupt the legitimate sequence, and forged publishers (already a
    // NEW_PUBLISHER) cannot grow the state without bound.
    if (!known || known.srcMac !== e.srcMac) return;
    const values = e.values.join(",");
    const s = this.state.get(key);
    if (!s) {
      this.state.set(key, { stNum: e.stNum, sqNum: e.sqNum, values, lastSeen: e.tMs, anchorSeen: e.tMs, talSeen: e.timeAllowedToLive, expired: false });
      return;
    }
    const tal = this.trustedTal(known, s);

    if (e.stNum >= s.stNum) {
      // The anchor continues, so anything lower is not a restart: the shadow loses its claim to
      // replace the anchor but keeps its rules, so forged values on it are still caught. If a
      // never-adopted shadow climbs back to here, its frames meet the anchor's rules: extra alerts,
      // never silence.
      if (s.shadow) s.shadow.restartEvidence = false;
      s.anchorSeen = e.tMs;
      s.talSeen = Math.max(s.talSeen, e.timeAllowedToLive);
      const advances = e.stNum > s.stNum || e.sqNum > s.sqNum;
      // Only a frame that moves the sequence on proves the publisher is alive: a replayed copy of
      // the last frame, or a rejected forged value, must not hold off TTL_EXPIRY.
      if (this.step(s, e, values) && advances) {
        s.lastSeen = e.tMs;
        s.expired = false;
      }
      return;
    }

    // Never let a lower sequence rewind the anchor: follow it as a shadow instead.
    this.raise("STNUM_REGRESSION", e, { stNum: e.stNum, lastStNum: s.stNum }, key, String(e.stNum));
    const sh = s.shadow;
    if (!sh || e.stNum < sh.stNum) {
      const age = e.pduTMs === null ? null : e.tMs - e.pduTMs;
      const restartEvidence = e.tMs - s.anchorSeen > tal && age !== null && age >= -FUTURE_SKEW_MS && age <= FRESH_MS;
      s.shadow = { stNum: e.stNum, sqNum: e.sqNum, values, frames: 1, since: e.tMs, restartEvidence };
      return;
    }
    const advances = e.stNum > sh.stNum || e.sqNum > sh.sqNum; // a duplicate frame confirms nothing
    if (e.stNum === sh.stNum && e.sqNum < sh.sqNum) sh.restartEvidence = false; // a sequence that rewinds is no reboot
    if (!this.step(sh, e, values) || !advances) return;
    s.lastSeen = e.tMs; // a sequence that moves on is a live publisher, whichever one it is
    s.expired = false;
    sh.frames += 1;
    if (sh.restartEvidence && sh.frames >= RESTART_FRAMES && e.tMs - sh.since >= Math.max(RESTART_TAL_WINDOWS * tal, RESTART_MIN_MS)) {
      s.stNum = sh.stNum;
      s.sqNum = sh.sqNum;
      s.values = sh.values;
      s.anchorSeen = e.tMs;
      s.lastSeen = e.tMs;
      s.expired = false;
      s.shadow = undefined;
    }
  }

  /**
   * The sequence rules for one frame on one sequence (the anchor or a shadow), for a frame whose
   * stNum is not lower than the sequence's. Returns false when the frame must not advance it.
   */
  private step(q: Sequence, e: GooseEvent, values: string): boolean {
    if (e.stNum > q.stNum + 1) {
      this.raise("STNUM_JUMP", e, { stNum: e.stNum, lastStNum: q.stNum });
    } else if (e.stNum === q.stNum) {
      if (e.sqNum < q.sqNum) this.raise("SQNUM_RESET", e, { sqNum: e.sqNum, lastSqNum: q.sqNum, stNum: e.stNum });
      if (values !== q.values) {
        const changed = changedMembers(q.values, values, this.known.get(streamKey(e))?.members);
        this.raise("DATA_WITHOUT_STNUM", e, { stNum: e.stNum, sqNum: e.sqNum, ...(changed && { changed }) });
        return false; // a forged value never advances the sequence
      }
    }
    q.stNum = e.stNum;
    q.sqNum = e.sqNum;
    q.values = values;
    return true;
  }

  /** The TAL that silence is timed against: the learned one, or the anchor's own largest. Never one frame's. */
  private trustedTal(known: BaselineEntry, s: StreamState): number {
    return known.timeAllowedToLive ?? s.talSeen;
  }

  /**
   * Key for an unknown stream's alerts: its own while under the bound, one shared key past it.
   * When full, the oldest stream idle for UNKNOWN_IDLE_MS gives its slot (and its open alerts) back.
   */
  private admitUnknown(key: string, now: number): string {
    if (this.unknown.has(key)) {
      this.unknown.set(key, now);
      return key;
    }
    if (this.unknown.size >= MAX_UNKNOWN_STREAMS) {
      const idle = [...this.unknown].find(([, seen]) => now - seen > UNKNOWN_IDLE_MS);
      if (!idle) return UNKNOWN_OVERFLOW_KEY;
      this.unknown.delete(idle[0]);
      for (const cls of Object.keys(RULE_SEVERITY)) this.open.delete(`${cls}|${idle[0]}`);
    }
    this.unknown.set(key, now);
    return key;
  }
}

/** The top-level items of tshark's raw allData ("83:01:00:84:03:03:00:00"), one BER TLV each; null if it is not that. */
export function dataItems(raw: string): string[] | null {
  if (!/^[0-9a-f]{2}(:[0-9a-f]{2})*$/i.test(raw)) return null;
  const b = raw.split(":");
  const items: string[] = [];
  for (let i = 0; i < b.length; ) {
    let len = parseInt(b[i + 1] ?? "", 16), head = 2;
    if (Number.isNaN(len)) return null;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 3 || i + 2 + n > b.length) return null;
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + parseInt(b[i + 2 + k]!, 16);
      head += n;
    }
    if (i + head + len > b.length) return null;
    items.push(b.slice(i, i + head + len).join(":"));
    i += head + len;
  }
  return items;
}

/**
 * Which dataset members differ between two allData values, by SCD name or as "#index" without one.
 * For display only; the rule compares the whole value. Undefined when the values cannot be split.
 */
export function changedMembers(before: string, after: string, members?: string[]): string | undefined {
  const a = dataItems(before), b = dataItems(after);
  if (!a || !b) return undefined;
  const idx: number[] = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) idx.push(i);
  if (!idx.length) return undefined;
  const named = idx.map((i) => (members?.[i] !== undefined ? safeText(members[i]!, 60) : `#${i}`));
  return safeText(named.slice(0, 4).join(", ") + (named.length > 4 ? ` +${named.length - 4} more` : ""), 200);
}

// Strip what could act on a terminal, flip text direction or hide text from a reader before display:
// ASCII and Latin-1 control characters, soft hyphen, Arabic letter mark, zero-width and bidi controls, line/paragraph
// separators, invisible operators, BOM and Unicode tag characters (invisible to people, read by models).
export function safeText(s: string, max = 120): string {
  const cleaned = s.replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\u{e0000}-\u{e007f}]/gu, "\ufffd");
  return cleaned.length > max ? cleaned.slice(0, max - 1) + "…" : cleaned;
}
