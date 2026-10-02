// Evaluate one local System One model on the fixed gold set.
// usage: bun src/eval.ts <model> [--base http://127.0.0.1:11434] [--gold gold/gold.json] [--out reports/]

import { mkdirSync } from "node:fs";
import type { GoldCase } from "./gold";
import { CAUSES, SystemOneAdapter, type Cause, type TriageResult } from "./triage";
import { triage2 } from "./pack2";

// Fixed in docs/EVAL.md before the first model run. Do not tune on this gold set.
export const STOP_RULE = {
  gate: 0.6,
  minValidRate: 0.95,
  minPrecisionPerLabel: 0.8,
  minConfidentPerLabelForCheck: 5,
  minConfidentAccuracy: 0.8,
  maxNotSureRate: 0.4,
} as const;

export function wilson(k: number, n: number, z = 1.96): [number, number] {
  if (n === 0) return [0, 1];
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}

const pct = (xs: number[], q: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))]! : NaN;
};

export function score(cases: GoldCase[], results: TriageResult[]) {
  const labels = ["cyberattack", "maintenance", "device_fault"] as const;
  const rows = cases.map((c, i) => ({ c, r: results[i]! }));
  const valid = rows.filter((x) => x.r.ok);
  const confident = valid.filter((x) => x.r.ok && x.r.triage.causeP >= STOP_RULE.gate && x.r.triage.causeWinner !== "unclear");
  const pred = (x: (typeof rows)[number]) => (x.r.ok ? x.r.triage.causeWinner : null);
  const perLabel = Object.fromEntries(labels.map((l) => {
    const predicted = confident.filter((x) => pred(x) === l);
    const tp = predicted.filter((x) => x.c.label === l).length;
    const actual = rows.filter((x) => x.c.label === l).length;
    const found = confident.filter((x) => x.c.label === l && pred(x) === l).length;
    return [l, { predicted: predicted.length, tp, precision: predicted.length ? tp / predicted.length : null,
      precisionWilson: wilson(tp, predicted.length), recall: found / actual, actual }];
  }));
  const correct = confident.filter((x) => pred(x) === x.c.label).length;
  const brier = valid.length
    ? valid.reduce((s, x) => {
        if (!x.r.ok) return s;
        const p = x.r.triage.cause;
        return s + (Object.keys(CAUSES) as Cause[]).reduce((t, k) => t + (p[k] - (k === x.c.label ? 1 : 0)) ** 2, 0);
      }, 0) / valid.length
    : null;
  const lat = valid.map((x) => (x.r.ok ? x.r.triage.latencyMs : 0));
  const m = {
    n: rows.length,
    validRate: valid.length / rows.length,
    notSureRate: valid.length ? 1 - confident.length / valid.length : 1,
    confidentAccuracy: confident.length ? correct / confident.length : null,
    confidentAccuracyWilson: wilson(correct, confident.length),
    brier,
    latencyMs: { p50: pct(lat, 0.5), p95: pct(lat, 0.95) },
    perLabel,
    failures: rows.filter((x) => !x.r.ok).map((x) => ({ id: x.c.id, failure: x.r.ok ? "" : x.r.failure })),
  };
  const reasons: string[] = [];
  if (m.validRate < STOP_RULE.minValidRate) reasons.push(`valid ${m.validRate.toFixed(2)} < ${STOP_RULE.minValidRate}`);
  if (m.notSureRate > STOP_RULE.maxNotSureRate) reasons.push(`not-sure ${m.notSureRate.toFixed(2)} > ${STOP_RULE.maxNotSureRate}`);
  if (m.confidentAccuracy === null || m.confidentAccuracy < STOP_RULE.minConfidentAccuracy) reasons.push(`confident accuracy ${m.confidentAccuracy?.toFixed(2) ?? "n/a"} < ${STOP_RULE.minConfidentAccuracy}`);
  for (const l of labels) {
    const r = perLabel[l]!;
    if (r.predicted >= STOP_RULE.minConfidentPerLabelForCheck && (r.precision ?? 0) < STOP_RULE.minPrecisionPerLabel)
      reasons.push(`${l} precision ${r.tp}/${r.predicted} < ${STOP_RULE.minPrecisionPerLabel}`);
  }
  return { ...m, verdict: reasons.length ? "STOP" : "PASS", reasons };
}

if (import.meta.main) {
  const args = Bun.argv.slice(2);
  const model = args[0];
  if (!model) { console.error("usage: bun src/eval.ts <model> [--base url] [--gold file] [--out dir]"); process.exit(2); }
  const opt = (n: string, d: string) => (args.includes(n) ? args[args.indexOf(n) + 1]! : d);
  const gold = (await Bun.file(opt("--gold", "gold/gold.json")).json()) as { cases: GoldCase[] };
  const adapter = new SystemOneAdapter(opt("--base", "http://127.0.0.1:11434"), model, 120_000);
  const results: TriageResult[] = [];
  for (const c of gold.cases) {
    const r = opt("--pack", "1") === "2" ? await triage2(adapter, c.alert) : await adapter.triage(c.alert, c.alert.context);
    results.push(r);
    process.stderr.write(`${c.id.padEnd(26)} ${c.label.padEnd(13)} ${r.ok ? `${r.triage.causeWinner} ${r.triage.causeP.toFixed(2)} ${Math.round(r.triage.latencyMs)}ms` : `FAIL ${r.failure}`}\n`);
  }
  const report = { model, at: new Date().toISOString(), stopRule: STOP_RULE, ...score(gold.cases, results),
    predictions: gold.cases.map((c, i) => ({ id: c.id, label: c.label, result: results[i] })) };
  const out = opt("--out", "reports");
  mkdirSync(out, { recursive: true });
  const tag = opt("--pack", "1") === "2" ? "-pack2" : "";
  const goldTag = opt("--gold", "gold/gold.json").includes("v2") ? "-goldv2" : "";
  const file = `${out}/eval-${model.replace(/[^a-z0-9.]+/gi, "_")}${tag}${goldTag}.json`;
  await Bun.write(file, JSON.stringify(report, null, 2) + "\n");
  console.log(`${model}: ${report.verdict}${report.reasons.length ? " (" + report.reasons.join("; ") + ")" : ""} → ${file}`);
}
