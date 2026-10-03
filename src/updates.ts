// What a consumer of the alert stream should print for each rule event. A new alert always; a repeat
// folded into an open alert at most once per `everyMs`, so a condition that keeps going (or an
// attacker hiding behind one) stays visible downstream without one line per frame.

import type { Alert } from "./rules";

export const UPDATE_EVERY_MS = 10_000;

/** The JSON line for a repeat: which alert (class, stream, first time), how many so far, the latest time. */
export interface AlertUpdate {
  update: { cls: Alert["cls"]; key: string; tMs: number };
  count: number;
  lastMs: number;
}

export function updateGate(everyMs = UPDATE_EVERY_MS) {
  const shown = new WeakMap<Alert, number>();
  return (a: Alert, isNew: boolean): "new" | AlertUpdate | null => {
    if (isNew) {
      shown.set(a, a.tMs);
      return "new";
    }
    if (a.lastMs - (shown.get(a) ?? a.tMs) < everyMs) return null;
    shown.set(a, a.lastMs);
    return { update: { cls: a.cls, key: a.key, tMs: a.tMs }, count: a.count, lastMs: a.lastMs };
  };
}
