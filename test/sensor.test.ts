// C42/C43/A8: the sensor heartbeat. A quiet bus must never look like a dead sensor, and back.
import { describe, expect, test } from "bun:test";
import { HEARTBEAT_MS, NO_GOOSE_MS, SENSOR_SILENT_MS, heartbeat, sensorState } from "../src/sensor";

describe("C43 the sensor state the board shows", () => {
  const t0 = 1_800_000_000_000;
  const beat = (frames: number, idleMs: number | null) => ({ tMs: t0, frames, idleMs });

  test("no heartbeat yet", () => {
    expect(sensorState(null, t0).state).toBe("none");
  });
  test("a fresh beat with recent frames is capturing, with the frame count", () => {
    const s = sensorState(beat(1234, 200), t0 + 1000);
    expect(s).toEqual({ state: "capturing", text: "capturing · 1,234 frames" });
  });
  test("silent exactly past the limit, not at it", () => {
    expect(sensorState(beat(5, 0), t0 + SENSOR_SILENT_MS).state).toBe("capturing");
    expect(sensorState(beat(5, 0), t0 + SENSOR_SILENT_MS + 1)).toEqual({ state: "silent", text: "sensor silent 15 s" });
  });
  test("no GOOSE exactly past the limit, not at it", () => {
    expect(sensorState(beat(5, NO_GOOSE_MS), t0).state).toBe("capturing");
    expect(sensorState(beat(5, NO_GOOSE_MS + 1), t0)).toEqual({ state: "no-goose", text: "sensor up · no GOOSE 30 s" });
  });
  test("the time since the beat counts toward the bus idle time", () => {
    expect(sensorState(beat(5, NO_GOOSE_MS - 4000), t0 + 5000).state).toBe("no-goose");
  });
  test("a sensor that never saw a frame says so", () => {
    expect(sensorState(beat(0, null), t0 + 1000)).toEqual({ state: "no-goose", text: "sensor up · no GOOSE yet" });
  });
  test("a dead sensor wins over an idle bus", () => {
    expect(sensorState(beat(0, null), t0 + SENSOR_SILENT_MS + 1).state).toBe("silent");
  });
  test("thresholds: three missed beats, and silence well beyond any publisher's retransmit", () => {
    expect(SENSOR_SILENT_MS).toBe(3 * HEARTBEAT_MS);
    expect(NO_GOOSE_MS).toBeGreaterThan(SENSOR_SILENT_MS);
  });
});

describe("C42 the heartbeat line", () => {
  test("carries wall time, frames and idle time", () => {
    expect(heartbeat(10_000, 7, 9_500)).toEqual({ heartbeat: { tMs: 10_000, frames: 7, idleMs: 500 } });
    expect(heartbeat(10_000, 0, null)).toEqual({ heartbeat: { tMs: 10_000, frames: 0, idleMs: null } });
  });

  const args = ["src/cli.ts", "run", "--baseline", "fixtures/baseline.json", "--json"];
  const lines = (out: string) => out.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

  const piped = async (hold: number) => {
    const p = Bun.spawn(["bash", "-c", `(cat fixtures/replay.pcap; sleep ${hold}) | bun ${args.join(" ")} --stdin`], { stdout: "pipe", stderr: "ignore" });
    const out = lines(await new Response(p.stdout).text());
    expect(await p.exited).toBe(0);
    return out;
  };

  test("live run writes a beat at start and every 5 s, with the frames it saw", async () => {
    const t = Date.now();
    const out = await piped(6); // held open 6 s, so the publishers also go silent: TTL_EXPIRY is expected here
    const beats = out.filter((o) => o.heartbeat).map((o) => o.heartbeat);
    expect(beats.length).toBeGreaterThanOrEqual(2);
    expect(beats[0].frames).toBe(0);
    expect(beats[0].tMs).toBeGreaterThanOrEqual(t);
    const last = beats.at(-1);
    expect(last.frames).toBeGreaterThan(0);
    expect(last.idleMs).toBeGreaterThanOrEqual(0);
    expect(beats[1].tMs - beats[0].tMs).toBeGreaterThanOrEqual(HEARTBEAT_MS - 50);
    expect(out.every((o) => o.heartbeat || o.cls || o.update)).toBe(true);
  }, 30_000);

  test("A8: --file writes no beat, and live alerts are exactly the --file alerts", async () => {
    const byFile = lines(await new Response(Bun.spawn(["bun", ...args, "--file", "fixtures/replay.pcap"], { stdout: "pipe", stderr: "ignore" }).stdout).text());
    const out = await piped(1); // as in C33: held open just long enough for the timer to tick
    expect(byFile.filter((o) => o.heartbeat)).toEqual([]);
    expect(out.filter((o) => o.heartbeat).length).toBeGreaterThanOrEqual(1);
    const alerts = (xs: any[]) => JSON.stringify(xs.filter((o) => o.cls).map(({ cls, key, severity, tMs }) => ({ cls, key, severity, tMs })));
    expect(alerts(out)).toBe(alerts(byFile));
  }, 30_000);
});
