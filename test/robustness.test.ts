// C26-C28: the rule engine survives a relay restart, malformed frames and a flood of forged publishers.
import { describe, expect, test } from "bun:test";
import type { GooseEvent } from "../src/decode";
import { invalidFields, learn, MAX_ALERTS, MAX_UNKNOWN_STREAMS, RuleEngine, UNKNOWN_OVERFLOW_KEY } from "../src/rules";
import { Backlog } from "../src/backlog";

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
  test("after a restart, a normal state change raises nothing new", () => {
    const { classes } = run([...heartbeat(5, 0, 3), ...heartbeat(1, 0, 10), ...heartbeat(2, 0, 3, ["False"])]);
    expect(classes).toEqual(["STNUM_REGRESSION"]);
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

describe("C28 a flood of forged publishers stays bounded", () => {
  test("unknown streams past the bound fold into one alert and keep no state", () => {
    const n = 5_000;
    const { engine } = run(Array.from({ length: n }, (_, i) => ({ gocbRef: `X${i}`, test: true })));
    const overflow = engine.alerts.filter((a) => a.key === UNKNOWN_OVERFLOW_KEY);
    expect(overflow.length).toBe(1);
    expect(overflow[0]!.cls).toBe("NEW_PUBLISHER");
    expect(engine.alerts.length).toBe(2 * MAX_UNKNOWN_STREAMS + 1); // NEW_PUBLISHER + TEST_MODE per admitted stream
    expect((engine as unknown as { state: Map<string, unknown> }).state.size).toBe(0);
  });
  test("malformed frames from unknown streams share the same bound", () => {
    const { engine } = run(Array.from({ length: 2_000 }, (_, i) => ({ gocbRef: `M${i}`, stNum: NaN })));
    expect(engine.alerts.length).toBe(MAX_UNKNOWN_STREAMS + 1);
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
