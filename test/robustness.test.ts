// C26-C28: the rule engine survives a relay restart, malformed frames and a flood of forged publishers.
import { describe, expect, test } from "bun:test";
import type { GooseEvent } from "../src/decode";
import { invalidFields, learn, MAX_ALERTS, MAX_UNKNOWN_STREAMS, RuleEngine, UNKNOWN_OVERFLOW_KEY } from "../src/rules";
import { Backlog } from "../src/backlog";
import { parseEkLine } from "../src/decode";
import { updateGate } from "../src/updates";

const ev = (o: Partial<GooseEvent>): GooseEvent => ({
  tMs: 0, srcMac: "02:00:00:00:00:01", dstMac: "01:0c:cd:01:00:01", vlanId: null, appId: 1, simulationBit: false,
  gocbRef: "BAY1/LLN0$GO$gcb", timeAllowedToLive: 2000, datSet: "BAY1/LLN0$ds", goID: "g", pduTMs: null,
  stNum: 5, sqNum: 3, test: false, confRev: 1, ndsCom: false, numDatSetEntries: 1, values: ["True"], ...o,
});
const baseline = learn([ev({})]);

/** Feed frames one second apart; returns "CLASS×count" in raise order. */
function run(frames: Partial<GooseEvent>[], engine = new RuleEngine(baseline)) {
  frames.forEach((f, i) => engine.ingest(ev({ tMs: 1000 * (i + 1), ...f })));
  return { engine, classes: engine.alerts.map((a) => a.cls) };
}
const heartbeat = (stNum: number, from: number, n: number, values = ["True"]) =>
  Array.from({ length: n }, (_, i) => ({ stNum, sqNum: from + i, values }));

describe("C26 a relay restart re-arms the rules", () => {
  test("after a restart, a forged value is still caught", () => {
    const { classes } = run([...heartbeat(5, 0, 3), ...heartbeat(1, 0, 20), { stNum: 1, sqNum: 30, values: ["False"] }]);
    expect(classes).toEqual(["STNUM_REGRESSION", "DATA_WITHOUT_STNUM"]);
  });
  test("after a restart, a state change on the followed sequence surfaces as its own regression and nothing else", () => {
    const { classes } = run([...heartbeat(5, 0, 3), ...heartbeat(1, 0, 10), ...heartbeat(2, 0, 3, ["False"])]);
    expect(classes).toEqual(["STNUM_REGRESSION", "STNUM_REGRESSION"]);
  });
  test("a forged value inside the restart window is caught too", () => {
    const { classes } = run([...heartbeat(5, 0, 3), ...heartbeat(1, 0, 2), { stNum: 1, sqNum: 2, values: ["False"] }]);
    expect(classes).toEqual(["STNUM_REGRESSION", "DATA_WITHOUT_STNUM"]);
  });
  test("a replay next to a live publisher is never adopted", () => {
    // Old frames (stNum 1, rising sqNum) interleaved with the live stream (stNum 5) for a minute.
    const mixed = Array.from({ length: 60 }, (_, i) => (i % 2 ? { stNum: 5, sqNum: 10 + i } : { stNum: 1, sqNum: i }));
    const { engine, classes } = run([...heartbeat(5, 0, 3), ...mixed]);
    expect(classes).toEqual(["STNUM_REGRESSION"]);
    // Still anchored on the live stream: stNum 6 is normal, stNum 9 is a jump.
    run([{ stNum: 6, sqNum: 0 }], engine);
    expect(engine.alerts.map((a) => a.cls)).toEqual(["STNUM_REGRESSION"]);
    engine.ingest(ev({ tMs: 70_000, stNum: 9, sqNum: 0 }));
    expect(engine.alerts.at(-1)!.cls).toBe("STNUM_JUMP");
  });
});

describe("C26 the lower sequence is adopted only with restart evidence", () => {
  // Anchor at stNum 5 for 3 s, then 6 s of silence, then a lower sequence, one frame per second.
  // `age` is the PDU timestamp's age on arrival: fresh after a reboot, old in a replay.
  function afterSilence(age: number, n: number) {
    const engine = new RuleEngine(baseline);
    for (let i = 1; i <= 3; i++) engine.ingest(ev({ tMs: i * 1000, pduTMs: 0, stNum: 5, sqNum: i }));
    for (let i = 0; i < n; i++) {
      const tMs = 10_000 + i * 1000;
      engine.ingest(ev({ tMs, pduTMs: tMs - age, stNum: 1, sqNum: i }));
    }
    return { engine, regression: () => engine.alerts.find((a) => a.cls === "STNUM_REGRESSION")!.count };
  }
  test("a reboot (silence, fresh timestamp) is adopted after 10 s and stops recurring", () => {
    const { engine, regression } = afterSilence(0, 11);
    expect(engine.alerts.map((a) => [a.cls, a.severity])).toEqual([["TTL_EXPIRY", 3], ["STNUM_REGRESSION", 3]]);
    expect(regression()).toBe(11);
    for (let i = 11; i < 30; i++) engine.ingest(ev({ tMs: 10_000 + i * 1000, pduTMs: 10_000, stNum: 1, sqNum: i }));
    expect(regression()).toBe(11); // adopted after 10 s: the stream is normal again
    engine.ingest(ev({ tMs: 41_000, pduTMs: 10_000, stNum: 1, sqNum: 31, values: ["False"] }));
    expect(engine.alerts.at(-1)!.cls).toBe("DATA_WITHOUT_STNUM"); // and fully armed
  });
  test("a replay after silence carries an old timestamp and is never adopted", () => {
    const { regression } = afterSilence(60_000, 20);
    expect(regression()).toBe(20); // every replayed frame keeps the alarm live
  });
  test("a stream that was not silent is never adopted, even with a fresh timestamp", () => {
    const engine = new RuleEngine(baseline);
    for (let i = 1; i <= 23; i++) engine.ingest(ev({ tMs: i * 1000, pduTMs: i * 1000, ...(i <= 3 ? { stNum: 5, sqNum: i } : { stNum: 1, sqNum: i }) }));
    expect(engine.alerts.find((a) => a.cls === "STNUM_REGRESSION")!.count).toBe(20);
  });
  test("a jump inside the followed sequence is caught", () => {
    const { classes } = run([...heartbeat(5, 0, 3), ...heartbeat(1, 0, 2), { stNum: 3, sqNum: 0 }]);
    expect(classes).toEqual(["STNUM_REGRESSION", "STNUM_REGRESSION", "STNUM_JUMP"]);
  });
});

describe("C27 a malformed frame never resets a stream", () => {
  test("NaN stNum raises MALFORMED_PDU and the replay after it is still a regression", () => {
    const { classes } = run([...heartbeat(5, 0, 3), { stNum: NaN }, { stNum: 2, sqNum: 1, values: ["False"] }]);
    expect(classes).toEqual(["MALFORMED_PDU", "STNUM_REGRESSION"]);
  });
  test("every header field the rules use is validated", () => {
    const cases: [Partial<GooseEvent>, string][] = [
      [{ stNum: NaN }, "stNum"], [{ stNum: -1 }, "stNum"], [{ stNum: 2 ** 32 }, "stNum"], [{ sqNum: 1.5 }, "sqNum"],
      [{ timeAllowedToLive: 0 }, "timeAllowedToLive"], [{ timeAllowedToLive: NaN }, "timeAllowedToLive"],
      [{ confRev: NaN }, "confRev"], [{ numDatSetEntries: NaN }, "numDatSetEntries"], [{ appId: 0x10000 }, "appId"], [{ tMs: NaN }, "time"],
    ];
    for (const [o, field] of cases) expect(invalidFields(ev(o))).toEqual([field]);
    expect(invalidFields(ev({}))).toEqual([]);
  });
});

describe("C26 frame fields cannot buy an adoption", () => {
  test("forged TAL, fresh t and duplicate frames next to a live publisher are never adopted", () => {
    // The bypass found in review: the live publisher heartbeats at stNum 10; the attacker clones its
    // MAC and sends three identical stNum 9 frames with TAL 1 ms and a fresh t, then the live
    // stNum 10 heartbeat arrives. It must still read as the live anchor, with the replay alarmed.
    const engine = new RuleEngine(baseline);
    for (let i = 1; i <= 3; i++) engine.ingest(ev({ tMs: i * 1000, stNum: 10, sqNum: i }));
    for (const tMs of [3_100, 3_101, 3_102]) engine.ingest(ev({ tMs, pduTMs: tMs, stNum: 9, sqNum: 0, timeAllowedToLive: 1 }));
    engine.ingest(ev({ tMs: 4_000, stNum: 10, sqNum: 4 }));
    engine.ingest(ev({ tMs: 5_000, stNum: 11, sqNum: 0, values: ["False"] }));
    expect(engine.alerts.map((a) => a.cls)).toEqual(["STNUM_REGRESSION"]);
  });
  test("a frame cannot stretch the silence a TTL is timed against", () => {
    const engine = new RuleEngine(baseline);
    engine.ingest(ev({ tMs: 1_000 }));
    engine.ingest(ev({ tMs: 2_000, sqNum: 4, timeAllowedToLive: 0xffff_ffff }));
    engine.tick(10_000);
    expect(engine.alerts.map((a) => a.cls)).toEqual(["CONFIG_CHANGE", "TTL_EXPIRY"]);
  });

  // A lower sequence after 6 s of silence. `frames` are [ms after 10 s, PDU timestamp age, stNum,
  // sqNum]; the anchor (stNum 5) may speak in between. Returns whether the lower sequence was adopted:
  // a probe at stNum 5 is normal for the old anchor and a jump for an adopted stNum-1 sequence.
  function adopted(frames: [number, number, number, number][], anchorAt: number[] = []) {
    const engine = new RuleEngine(baseline);
    for (let i = 1; i <= 3; i++) engine.ingest(ev({ tMs: i * 1000, stNum: 5, sqNum: i }));
    const all = [...frames.map(([dt, age, stNum, sqNum]) => ({ tMs: 10_000 + dt, pduTMs: 10_000 + dt - age, stNum, sqNum })),
      ...anchorAt.map((dt, i) => ({ tMs: 10_000 + dt, pduTMs: 0, stNum: 5, sqNum: 10 + i }))].sort((a, b) => a.tMs - b.tMs);
    for (const f of all) engine.ingest(ev(f));
    engine.ingest(ev({ tMs: 59_000, stNum: 5, sqNum: 50 }));
    return engine.alerts.at(-1)!.cls === "STNUM_JUMP";
  }
  const steady = (n: number, gapMs: number, age = 0): [number, number, number, number][] =>
    Array.from({ length: n }, (_, i) => [i * gapMs, age, 1, i]);

  test("adoption needs three advancing frames, not just time", () => {
    expect(adopted(steady(2, 12_000))).toBe(false); // two frames over 12 s
    expect(adopted(steady(3, 6_000))).toBe(true); // three frames over 12 s
    expect(adopted(steady(3, 4_000))).toBe(false); // three frames over 8 s: under the 10 s floor
  });
  test("a timestamp from the future beyond 1 s of skew is not fresh", () => {
    expect(adopted(steady(12, 1_000, -2_000))).toBe(false);
    expect(adopted(steady(12, 1_000, -500))).toBe(true);
    expect(adopted(steady(12, 1_000, 6_000))).toBe(false); // and one older than 5 s is a replay
  });
  test("one frame from the old sequence cancels a restart in progress", () => {
    expect(adopted(steady(12, 1_000))).toBe(true);
    expect(adopted(steady(12, 1_000), [3_500])).toBe(false);
  });
  test("a regression to a different stNum is a new alert, not a fold", () => {
    // A stale replay every 9 s keeps one alert open; a forged stNum 4 later must surface on its own.
    const engine = new RuleEngine(baseline);
    for (let t = 1_000; t <= 120_000; t += 1_000) engine.ingest(ev({ tMs: t, stNum: 10, sqNum: t / 1000 }));
    for (let t = 3_200; t < 100_000; t += 9_000) engine.ingest(ev({ tMs: t, pduTMs: 0, stNum: 1, sqNum: 0 }));
    engine.ingest(ev({ tMs: 103_100, pduTMs: 103_100, stNum: 4, sqNum: 0, values: ["False"] }));
    const regressions = engine.alerts.filter((a) => a.cls === "STNUM_REGRESSION");
    expect(regressions.at(-1)!.detail.stNum).toBe(4);
    expect(regressions.at(-1)!.count).toBe(1);
  });
});

describe("C28 a flood of forged publishers stays bounded", () => {
  // A dense flood: one frame per millisecond, faster than any unknown stream can go idle.
  const flood = (n: number, f: (i: number) => Partial<GooseEvent>, engine = new RuleEngine(baseline)) => {
    for (let i = 0; i < n; i++) engine.ingest(ev({ tMs: i, ...f(i) }));
    return engine;
  };
  test("unknown streams past the bound fold into one alert and keep no state", () => {
    const engine = flood(5_000, (i) => ({ gocbRef: `X${i}`, test: true }));
    const overflow = engine.alerts.filter((a) => a.key === UNKNOWN_OVERFLOW_KEY);
    expect(overflow.map((a) => a.cls)).toEqual(["NEW_PUBLISHER"]);
    expect(engine.alerts.length).toBe(2 * MAX_UNKNOWN_STREAMS + 1); // NEW_PUBLISHER + TEST_MODE per admitted stream
    expect((engine as unknown as { state: Map<string, unknown> }).state.size).toBe(0);
  });
  test("a malformed frame from an unknown stream is still a new publisher, within the same bound", () => {
    const engine = flood(2_000, (i) => ({ gocbRef: `M${i}`, stNum: NaN }));
    expect(engine.alerts.slice(0, 2).map((a) => [a.cls, a.severity])).toEqual([["NEW_PUBLISHER", 3], ["MALFORMED_PDU", 2]]);
    expect(engine.alerts.length).toBe(2 * MAX_UNKNOWN_STREAMS + 2);
  });
  test("a rogue that arrives after the flood goes idle gets its own alert", () => {
    // The scenario from review: 256 junk streams once, then a new junk stream every 5 s; a real rogue at 70 s.
    const engine = flood(MAX_UNKNOWN_STREAMS, (i) => ({ gocbRef: `J${i}` }));
    for (let t = 5_000; t < 70_000; t += 5_000) engine.ingest(ev({ tMs: t, gocbRef: `late-junk-${t}` }));
    engine.ingest(ev({ tMs: 70_000, srcMac: "02:66:66:00:00:01", gocbRef: "ROGUE/LLN0$GO$trip" }));
    const rogue = engine.alerts.at(-1)!;
    expect([rogue.gocbRef, rogue.key === UNKNOWN_OVERFLOW_KEY]).toEqual(["ROGUE/LLN0$GO$trip", false]);
  });
  test("an overflow that keeps going is re-announced each minute, naming the latest offender", () => {
    const engine = flood(MAX_UNKNOWN_STREAMS + 1, (i) => ({ gocbRef: `K${i}` }));
    for (const t of [30_000, 60_000]) for (let k = 0; k < MAX_UNKNOWN_STREAMS; k++) engine.ingest(ev({ tMs: t + k, gocbRef: `K${k}` })); // keep every slot busy
    engine.ingest(ev({ tMs: 61_500, srcMac: "02:66:66:00:00:01", gocbRef: "ROGUE/LLN0$GO$trip" }));
    const overflow = engine.alerts.filter((a) => a.key === UNKNOWN_OVERFLOW_KEY);
    expect(overflow.length).toBe(2);
    expect(overflow[1]!.detail.latestGocbRef).toBe("ROGUE/LLN0$GO$trip");
  });
  test("the alert list is capped", () => {
    // One TEST_MODE alert every 11 s (past the dedupe window) on a known stream.
    const engine = new RuleEngine(baseline);
    for (let i = 0; i < MAX_ALERTS + 50; i++) engine.ingest(ev({ tMs: 11_000 * i, sqNum: i, test: true }));
    expect(engine.alerts.length).toBe(MAX_ALERTS);
  });
  test("the model backlog skips at once when full and drains afterwards", async () => {
    const b = new Backlog(2);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const skipped: number[] = [];
    for (let i = 0; i < 5; i++) b.run(() => gate, () => skipped.push(i));
    expect(skipped).toEqual([2, 3, 4]);
    release();
    await b.idle();
    expect(b.size).toBe(0);
  });
});

describe("Review round 3 (gpt-6-astra)", () => {
  test("C26 a replayed copy of the last frame does not keep a dead relay alive", () => {
    const engine = new RuleEngine(baseline);
    engine.ingest(ev({ tMs: 1_000, stNum: 5, sqNum: 3 }));
    for (let t = 2_000; t <= 10_000; t += 1_000) engine.ingest(ev({ tMs: t, stNum: 5, sqNum: 3 }));
    expect(engine.alerts.map((a) => a.cls)).toEqual(["TTL_EXPIRY"]);
  });
  test("C26 the anchor speaking does not blind the rules on the lower sequence", () => {
    const frames = Array.from({ length: 10 }, (_, i) =>
      i % 2 ? { stNum: 5, sqNum: 10 + i } : { stNum: 1, sqNum: i, values: [i === 4 ? "False" : "True"] });
    const { classes } = run([...heartbeat(5, 0, 3), ...frames]);
    expect(classes).toContain("DATA_WITHOUT_STNUM");
  });
  test("C26 a lower sequence that rewinds its sqNum is never adopted", () => {
    const engine = new RuleEngine(baseline);
    for (let i = 1; i <= 3; i++) engine.ingest(ev({ tMs: i * 1000, stNum: 5, sqNum: i }));
    for (const [t, sq] of [[10, 10], [15, 0], [16, 10], [20, 0], [21, 10], [26, 11], [32, 12]]) engine.ingest(ev({ tMs: t! * 1000, pduTMs: 10_000, stNum: 1, sqNum: sq! }));
    engine.ingest(ev({ tMs: 40_000, stNum: 5, sqNum: 50 }));
    expect(engine.alerts.at(-1)!.cls).not.toBe("STNUM_JUMP"); // stNum 5 is still the anchor
  });
  test("C28 the open-alert map is capped even when every entry is fresh", () => {
    const engine = new RuleEngine(baseline);
    engine.ingest(ev({ tMs: 0, stNum: 20_000, sqNum: 0 }));
    for (let i = 0; i < 3_000; i++) engine.ingest(ev({ tMs: 1 + i / 10, stNum: 10_000 + i, sqNum: 0 }));
    expect((engine as unknown as { open: Map<string, unknown> }).open.size).toBeLessThanOrEqual(1_024);
  });
  test("C28 the overflow alert names the latest offender as it folds", () => {
    const engine = new RuleEngine(baseline);
    for (let i = 0; i < MAX_UNKNOWN_STREAMS + 2; i++) engine.ingest(ev({ tMs: i, gocbRef: `X${i}` }));
    const overflow = engine.alerts.find((a) => a.key === UNKNOWN_OVERFLOW_KEY)!;
    expect([overflow.count, overflow.detail.latestGocbRef]).toEqual([2, `X${MAX_UNKNOWN_STREAMS + 1}`]);
  });
  test("C27 a GOOSE PDU without gocbRef or APPID is reported, not dropped or given APPID 0", () => {
    const line = (layers: Record<string, string[]>) => JSON.stringify({ timestamp: "0", layers: { frame_time_epoch: ["1.0"], eth_src: ["02:00:00:00:00:09"], goose_stNum: ["1"], goose_sqNum: ["0"], goose_timeAllowedtoLive: ["2000"], goose_confRev: ["1"], goose_numDatSetEntries: ["1"], ...layers } });
    const noRef = parseEkLine(line({ goose_appid: ["0x0001"] }))!;
    const noApp = parseEkLine(line({ goose_gocbRef: ["IED/LLN0$GO$x"] }))!;
    expect(invalidFields(noRef)).toEqual(["gocbRef"]);
    expect(invalidFields(noApp)).toEqual(["appId"]);
  });
});

describe("C31 a baseline publisher that never appears is reported", () => {
  test("once, after the start-up grace, and not before", () => {
    const engine = new RuleEngine(baseline);
    engine.tick(0);
    engine.tick(9_000);
    expect(engine.alerts).toEqual([]);
    for (const t of [10_500, 20_000, 60_000]) engine.tick(t);
    expect(engine.alerts.map((a) => [a.cls, a.detail.neverSeen])).toEqual([["TTL_EXPIRY", true]]);
  });
  test("a publisher that speaks within the grace is not reported", () => {
    const engine = new RuleEngine(baseline);
    engine.tick(0);
    for (let t = 1_000; t <= 30_000; t += 1_000) engine.ingest(ev({ tMs: t, sqNum: t / 1000 }));
    expect(engine.alerts).toEqual([]);
  });
});

describe("C32 repeats stay visible downstream", () => {
  test("a repeat is printed at most once per 10 s, with its running count", () => {
    const gate = updateGate();
    const out: unknown[] = [];
    const e2 = new RuleEngine(baseline, (a, isNew) => { const o = gate(a, isNew); if (o) out.push(o === "new" ? a.cls : [o.count, o.lastMs]); });
    for (let t = 1_000; t <= 25_000; t += 1_000) e2.ingest(ev({ tMs: t, sqNum: t / 1000, test: true }));
    expect(out).toEqual(["TEST_MODE", [11, 11_000], [21, 21_000]]);
  });
});
