// C34: properties over random frame sequences (seeded, so a failure always reproduces).
// After every frame: no stream state holds a non-finite number, the anchor never moves back
// unless restart evidence was possible, every bound holds, and severities are the rule's.
import { describe, expect, test } from "bun:test";
import type { GooseEvent } from "../src/decode";
import { learn, MAX_ALERTS, RULE_SEVERITY, RuleEngine } from "../src/rules";

function mulberry32(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PUBS = [1, 2, 3].map((i) => ({ appId: i, gocbRef: `IED${i}/LLN0$GO$gcb`, srcMac: `02:00:00:00:00:0${i}` }));
const base = (p: (typeof PUBS)[number]): GooseEvent => ({
  tMs: 0, srcMac: p.srcMac, dstMac: "01:0c:cd:01:00:01", vlanId: null, appId: p.appId, simulationBit: false, gocbRef: p.gocbRef,
  timeAllowedToLive: 2000, datSet: "ds", goID: "g", pduTMs: null, stNum: 100, sqNum: 0, test: false, confRev: 1, ndsCom: false,
  numDatSetEntries: 1, values: ["True"],
});
const baseline = learn(PUBS.map(base));

/** One random frame: mostly plausible traffic on the known streams, with forgeries and garbage mixed in. */
function frame(r: () => number, tMs: number, withT: boolean): GooseEvent {
  const pick = <T,>(xs: T[]) => xs[Math.floor(r() * xs.length)]!;
  const p = pick(PUBS);
  const e = base(p);
  e.tMs = tMs;
  e.stNum = Math.max(0, 100 + Math.floor((r() - 0.5) * 20));
  e.sqNum = Math.floor(r() * 50);
  e.values = [pick(["True", "False"])];
  e.timeAllowedToLive = pick([2000, 2000, 2000, 1, 0xffff_ffff]);
  if (withT) e.pduTMs = tMs - pick([0, 0, 3_000, 60_000, -2_000]);
  if (r() < 0.1) e.srcMac = "02:66:66:00:00:01"; // spoofer
  if (r() < 0.05) e.gocbRef = `ROGUE${Math.floor(r() * 400)}`; // unknown publishers
  if (r() < 0.05) e.test = true;
  if (r() < 0.05) Object.assign(e, pick<Partial<GooseEvent>>([{ stNum: NaN }, { sqNum: -1 }, { timeAllowedToLive: NaN }, { appId: NaN }, { gocbRef: "" }, { confRev: NaN }]));
  return e;
}

type Inner = { state: Map<string, Record<string, unknown>>; open: Map<string, unknown> };

function check(seed: number, withT: boolean) {
  const r = mulberry32(seed);
  const engine = new RuleEngine(baseline);
  const inner = engine as unknown as Inner;
  let t = 0;
  const lastAnchor = new Map<string, number>();
  for (let i = 0; i < 200; i++) {
    t += Math.floor(r() * 3_000);
    engine.ingest(frame(r, t, withT));
    for (const [key, s] of inner.state) {
      for (const [k, v] of Object.entries(s)) if (typeof v === "number" && !Number.isFinite(v)) throw new Error(`seed ${seed}: ${key}.${k} = ${v}`);
      // Without PDU timestamps no restart evidence exists, so the anchor's stNum can only grow.
      if (!withT && (s.stNum as number) < (lastAnchor.get(key) ?? 0)) throw new Error(`seed ${seed}: anchor ${key} rewound`);
      lastAnchor.set(key, s.stNum as number);
    }
    if (inner.state.size > PUBS.length || inner.open.size > 1_024 || engine.alerts.length > MAX_ALERTS) throw new Error(`seed ${seed}: bound broken`);
  }
  for (const a of engine.alerts) if (a.severity !== RULE_SEVERITY[a.cls]) throw new Error(`seed ${seed}: severity of ${a.cls}`);
  return engine.alerts.map((a) => `${a.cls}|${a.key}|${a.tMs}|${a.count}`).join(";");
}

describe("C34 properties over 1 000 random sequences", () => {
  test("no NaN in state, no rewound anchor, bounds and severities hold", () => {
    for (let seed = 1; seed <= 500; seed++) { check(seed, false); check(seed, true); }
  });
  test("the engine is deterministic: the same frames give the same alerts", () => {
    for (let seed = 1; seed <= 50; seed++) expect(check(seed, true)).toBe(check(seed, true));
  });
});
