#!/usr/bin/env bun
// goose-watch CLI: scenarios · learn · run

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { decode, decodeAll } from "./decode";
import { learn, RuleEngine, safeText, type Baseline } from "./rules";
import { generate, SCENARIOS } from "./scenarios";
import { writePcap } from "./goose";

const [cmd, ...args] = Bun.argv.slice(2);

function usage(): never {
  console.error(`usage:
  goose-watch scenarios <dir>                     write every synthetic scenario as <dir>/<name>.pcap
  goose-watch learn <pcap> <baseline.json>        learn the publisher baseline from a clean capture
  goose-watch run (--file <pcap> | --iface <if>) --baseline <baseline.json> [--json]`);
  process.exit(2);
}

function flag(name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

switch (cmd) {
  case "scenarios": {
    const dir = args[0] ?? usage();
    mkdirSync(dir, { recursive: true });
    for (const s of SCENARIOS) {
      const pkts = generate(s);
      await Bun.write(join(dir, `${s.name}.pcap`), writePcap(pkts));
      console.log(`${s.name}\t${pkts.length} frames\texpect: ${s.expect.join(",") || "silence"}`);
    }
    break;
  }
  case "learn": {
    const [pcap, out] = args;
    if (!pcap || !out) usage();
    const b = learn(await decodeAll(pcap));
    await Bun.write(out, JSON.stringify(b, null, 2) + "\n");
    console.log(`${b.publishers.length} publishers learned → ${out}`);
    break;
  }
  case "run": {
    const file = flag("--file");
    const iface = flag("--iface");
    const basePath = flag("--baseline");
    if ((!file && !iface) || !basePath) usage();
    const baseline = (await Bun.file(basePath).json()) as Baseline;
    const asJson = args.includes("--json");
    const engine = new RuleEngine(baseline, (a, isNew) => {
      if (!isNew) return;
      if (asJson) console.log(JSON.stringify(a));
      else console.log(`${new Date(a.tMs).toISOString()}  sev ${a.severity}  ${a.cls.padEnd(18)} ${safeText(a.gocbRef)}  ${a.srcMac}`);
    });
    if (iface) setInterval(() => engine.tick(Date.now()), 250);
    for await (const e of decode(file ? { file } : { iface: iface! })) engine.ingest(e);
    if (!asJson) console.error(`${engine.alerts.length} alerts`);
    break;
  }
  default:
    usage();
}
