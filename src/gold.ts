// Gold set for model evaluation. Labels come from how each case was BUILT,
// not from anyone's reading of the output, and are fixed before any model run.
//
// Honest limit: variants share a generator, so cases are not independent field
// samples. The eval measures whether a model reads these evidence patterns,
// not how it performs on a real substation.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeAll } from "./decode";
import { writePcap, type GooseFrame } from "./goose";
import { learn, RuleEngine, type Alert, type AlertClass, type Baseline } from "./rules";
import { generate, SCENARIOS, type Mutator, type Scenario } from "./scenarios";
import type { Cause } from "./triage";

interface Kind {
  name: string;
  label: Exclude<Cause, "unclear">;
  target: AlertClass; // the alert that carries the case
  build: (pub: number) => Mutator[];
}

const ROGUE = (now: number, emit: (f: GooseFrame, at: number) => void, test: boolean, mac: string) => {
  if (now >= 30_000 && now % 1000 === 0) emit({ dstMac: "01:0c:cd:01:00:99", srcMac: mac, vlanId: 10, appId: 0x0099, simulationBit: test,
    pdu: { gocbRef: test ? "TESTSET/LLN0$GO$gcbSim" : "ROGUE/LLN0$GO$gcb1", timeAllowedToLive: 2000, datSet: "X/LLN0$ds", goID: "X",
      t: Date.UTC(2026, 9, 1, 10, 0, 30), stNum: 1, sqNum: (now - 30_000) / 1000, test, confRev: 1, ndsCom: false,
      allData: [{ kind: "boolean", value: true }] } }, now);
};

export const KINDS: Kind[] = [
  // cyberattack
  { name: "rogue-publisher", label: "cyberattack", target: "NEW_PUBLISHER",
    build: (pub) => [(now, _p, emit) => ROGUE(now, emit, false, `02:66:66:66:66:${(pub + 1).toString(16).padStart(2, "0")}`)] },
  { name: "spoofed-mac", label: "cyberattack", target: "NEW_PUBLISHER",
    build: (pub) => [(now, pubs, emit) => { if (now === 30_000) { const p = pubs[pub]!;
      emit({ ...frame(p), srcMac: "02:66:66:66:66:02", pdu: { ...frame(p).pdu, stNum: p.stNum + 1, sqNum: 0, allData: [{ kind: "boolean", value: !p.value }] } }, now); } }] },
  { name: "replay", label: "cyberattack", target: "STNUM_REGRESSION",
    build: (pub) => [(now, pubs, emit) => { if (now === 40_000) { const p = pubs[pub]!;
      emit({ ...frame(p), pdu: { ...frame(p).pdu, stNum: p.stNum - 3, sqNum: 7, t: Date.UTC(2026, 9, 1, 10, 0, 1) } }, now); } }] },
  { name: "poisoning", label: "cyberattack", target: "STNUM_JUMP",
    build: (pub) => [(now, pubs, emit) => { if (now === 35_000) { const p = pubs[pub]!;
      emit({ ...frame(p), pdu: { ...frame(p).pdu, stNum: p.stNum + 100, sqNum: 0, t: Date.UTC(2026, 9, 1, 10, 0, 35), allData: [{ kind: "boolean", value: !p.value }] } }, now); } }] },
  { name: "forged-status", label: "cyberattack", target: "DATA_WITHOUT_STNUM",
    build: (pub) => [(now, pubs, emit) => { if (now === 42_000) { const p = pubs[pub]!;
      emit({ ...frame(p), pdu: { ...frame(p).pdu, allData: [{ kind: "boolean", value: !p.value }, { kind: "bitstring", bits: 13, value: 0 }] } }, now); } }] },
  // maintenance
  { name: "test-mode", label: "maintenance", target: "TEST_MODE",
    build: (pub) => [(now, pubs) => { pubs[pub]!.test = now >= 30_000 && now < 40_000; }] },
  { name: "simulation-bit", label: "maintenance", target: "SIM_BIT",
    build: (pub) => [(now, pubs) => { pubs[pub]!.simulationBit = now >= 30_000 && now < 35_000; }] },
  { name: "test-set", label: "maintenance", target: "NEW_PUBLISHER",
    build: (pub) => [(now, _p, emit) => ROGUE(now, emit, true, `02:7e:57:00:00:${(pub + 1).toString(16).padStart(2, "0")}`)] },
  { name: "config-in-test", label: "maintenance", target: "CONFIG_CHANGE",
    build: (pub) => [(now, pubs) => { if (now === 30_000) { pubs[pub]!.confRev = 2; pubs[pub]!.test = true; } }] },
  // device_fault
  { name: "link-loss", label: "device_fault", target: "TTL_EXPIRY",
    build: (pub) => [(now, pubs) => { pubs[pub]!.silent = now >= 30_000; }] },
  { name: "ied-restart", label: "device_fault", target: "STNUM_REGRESSION",
    build: (pub) => [(now, pubs) => {
      const p = pubs[pub]!;
      p.silent = now >= 30_000 && now < 38_000;
      if (now === 38_000) { p.stNum = 1; p.sqNum = 0; p.lastChange = 38_000; p.burstIdx = 0; p.next = now; }
    }] },
];

// Same frame shape the scenario publishers use (kept here so gold kinds can tweak single fields).
function frame(p: any): GooseFrame {
  return {
    dstMac: p.spec.dstMac, srcMac: p.spec.srcMac, vlanId: p.spec.vlanId, vlanPriority: 4, appId: p.spec.appId, simulationBit: p.simulationBit,
    pdu: { gocbRef: p.spec.gocbRef, timeAllowedToLive: 2000, datSet: p.spec.datSet, goID: p.spec.goID, t: Date.UTC(2026, 9, 1, 10) + p.lastChange,
      stNum: p.stNum, sqNum: p.sqNum, test: p.test, confRev: p.confRev, ndsCom: false,
      allData: [{ kind: "boolean", value: p.value }, { kind: "bitstring", bits: 13, value: p.quality }] },
  };
}

export interface GoldCase {
  id: string;
  kind: string;
  label: Exclude<Cause, "unclear">;
  alert: Alert;
}

/** device_fault kinds get two seeds so each label has >= 12 cases. */
export async function buildGold(seedBase = 100): Promise<GoldCase[]> {
  const dir = mkdtempSync(join(tmpdir(), "goose-gold-"));
  const basePcap = join(dir, "baseline.pcap");
  await Bun.write(basePcap, writePcap(generate(SCENARIOS[0]!)));
  const baseline: Baseline = learn(await decodeAll(basePcap));
  const cases: GoldCase[] = [];
  for (const k of KINDS) {
    const seeds = k.label === "device_fault" ? [seedBase, seedBase + 100] : [seedBase];
    for (const seed of seeds) for (const pub of [0, 1, 2]) {
      const s: Scenario = { name: `${k.name}-${pub}-${seed}`, description: "", expect: [], durationMs: 60_000, seed: seed + pub, mutators: k.build(pub) };
      const file = join(dir, `${s.name}.pcap`);
      await Bun.write(file, writePcap(generate(s)));
      const engine = new RuleEngine(baseline);
      for (const e of await decodeAll(file)) engine.ingest(e);
      const alert = engine.alerts.find((a) => a.cls === k.target);
      if (!alert) throw new Error(`gold case ${s.name} did not raise ${k.target}`);
      cases.push({ id: s.name, kind: k.name, label: k.label, alert });
    }
  }
  return cases;
}

if (import.meta.main) {
  const out = Bun.argv[2] ?? "gold/gold.json";
  const cases = await buildGold(Number(Bun.argv[3] ?? "100"));
  await Bun.write(out, JSON.stringify({ version: 1, labels: ["cyberattack", "maintenance", "device_fault"], cases }, null, 2) + "\n");
  const by = cases.reduce<Record<string, number>>((m, c) => ((m[c.label] = (m[c.label] ?? 0) + 1), m), {});
  console.log(`${cases.length} gold cases → ${out}`, by);
}
