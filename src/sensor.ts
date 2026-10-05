// The sensor's heartbeat. A quiet bus and a dead sensor look the same on a board that only shows
// alerts, so live `run --json` also writes a heartbeat line every few seconds and the board shows
// what it last heard: capturing, capturing but no GOOSE, sensor silent, or no sensor yet.

export const HEARTBEAT_MS = 5_000;
export const SENSOR_SILENT_MS = 15_000; // three missed heartbeats
export const NO_GOOSE_MS = 30_000; // a substation bus with publishers sends GOOSE at least every few seconds

/** One heartbeat line in the alert stream. `tMs` is the sensor's wall clock. */
export interface Heartbeat {
  heartbeat: { tMs: number; frames: number; idleMs: number | null }; // idleMs: since the last frame arrived; null before the first
}

export function heartbeat(nowMs: number, frames: number, lastFrameWallMs: number | null): Heartbeat {
  return { heartbeat: { tMs: nowMs, frames, idleMs: lastFrameWallMs === null ? null : nowMs - lastFrameWallMs } };
}

export type SensorState =
  | { state: "none"; text: string }
  | { state: "silent"; text: string }
  | { state: "no-goose"; text: string }
  | { state: "capturing"; text: string };

const secs = (ms: number) => `${Math.floor(ms / 1000)} s`;

/** What the board says about the sensor, from the last heartbeat it read and its own clock. */
export function sensorState(hb: Heartbeat["heartbeat"] | null, nowMs: number): SensorState {
  if (!hb) return { state: "none", text: "no sensor yet" };
  const age = nowMs - hb.tMs;
  if (age > SENSOR_SILENT_MS) return { state: "silent", text: `sensor silent ${secs(age)}` };
  const idle = hb.idleMs === null ? null : hb.idleMs + Math.max(0, age);
  if (idle === null || idle > NO_GOOSE_MS) return { state: "no-goose", text: idle === null ? "sensor up · no GOOSE yet" : `sensor up · no GOOSE ${secs(idle)}` };
  return { state: "capturing", text: `capturing · ${hb.frames.toLocaleString("en")} frames` };
}
