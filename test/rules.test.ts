import { beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeAll, type GooseEvent } from "../src/decode";
import { writePcap } from "../src/goose";
import { learn, RuleEngine, safeText, type Baseline } from "../src/rules";
import { generate, HOSTILE_REF, SCENARIOS } from "../src/scenarios";

const dir = mkdtempSync(join(tmpdir(), "goose-watch-"));
const events = new Map<string, GooseEvent[]>();
const generated = new Map<string, number>();
let baseline: Baseline;

beforeAll(async () => {
  for (const s of SCENARIOS) {
    const pkts = generate(s);
    generated.set(s.name, pkts.length);
    const file = join(dir, `${s.name}.pcap`);
    await Bun.write(file, writePcap(pkts));
    events.set(s.name, await decodeAll(file));
  }
  baseline = learn(events.get("baseline")!);
});

const run = (name: string) => {
  const e = new RuleEngine(baseline);
  for (const ev of events.get(name)!) e.ingest(ev);
  return e.alerts;
};

describe("C1/C2 scenarios decode losslessly through tshark", () => {
  for (const s of SCENARIOS) {
    test(s.name, () => {
      const evs = events.get(s.name)!;
      expect(evs.length).toBe(generated.get(s.name)!);
      for (const e of evs) {
        expect(e.gocbRef.length).toBeGreaterThan(0);
        expect(Number.isFinite(e.stNum) && Number.isFinite(e.sqNum) && e.timeAllowedToLive > 0).toBe(true);
      }
    });
  }
});

describe("C3/C4 every scenario raises exactly its expected classes", () => {
  for (const s of SCENARIOS) {
    test(`${s.name} → ${s.expect.join(",") || "silence"}`, () => {
      const classes: string[] = [...new Set(run(s.name).map((a) => a.cls))].sort();
      expect(classes).toEqual([...s.expect].sort());
    });
  }
  test("baseline learned three publishers", () => expect(baseline.publishers.length).toBe(3));
});

describe("C9 hostile strings", () => {
  test("hostile name raises the same alerts as a benign unknown publisher", () => {
    const strip = (n: string) => run(n).map((a) => [a.cls, a.severity, a.tMs, a.count]);
    expect(strip("hostile-name")).toEqual(strip("new-publisher"));
    expect(run("hostile-name")[0]!.gocbRef).toContain("Ignore previous instructions");
  });
  test("safeText neutralises control, escape and bidi characters", () => {
    const out = safeText(HOSTILE_REF, 500);
    expect(out).not.toMatch(/[\u0000-\u001f\u007f‮]/);
  });
});

describe("dedupe", () => {
  test("a recurring condition stays one alert with a count", () => {
    const a = run("hostile-name");
    expect(a.length).toBe(1);
    expect(a[0]!.count).toBeGreaterThan(10);
  });
});
