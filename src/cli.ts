#!/usr/bin/env bun
// goose-watch CLI: scenarios · learn · run

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { decode, decodeAll } from "./decode";
import { learn, RuleEngine, safeText, type Baseline } from "./rules";
import { generate, SCENARIOS } from "./scenarios";
import { pcapHeader, pcapRecord, readPcap, retime, writePcap } from "./goose";
import { RawSocket } from "./rawsock";

const [cmd, ...args] = Bun.argv.slice(2);

function usage(): never {
  console.error(`usage:
  goose-watch scenarios <dir>                     write every synthetic scenario as <dir>/<name>.pcap
  goose-watch learn <pcap> <baseline.json>        learn the publisher baseline from a clean capture
  goose-watch run (--file <pcap> | --iface <if> | --stdin) --baseline <baseline.json> [--json]
  goose-watch replay <pcap> --iface <gw*> [--speed <x>]   send a scenario into the isolated lab link
  goose-watch capture --iface <gw*>                       write a live pcap stream to stdout (lab link)`);
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
    const stdin = args.includes("--stdin");
    if ((!file && !iface && !stdin) || !basePath) usage();
    const baseline = (await Bun.file(basePath).json()) as Baseline;
    const asJson = args.includes("--json");
    const engine = new RuleEngine(baseline, (a, isNew) => {
      if (!isNew) return;
      if (asJson) console.log(JSON.stringify(a));
      else console.log(`${new Date(a.tMs).toISOString()}  sev ${a.severity}  ${a.cls.padEnd(18)} ${safeText(a.gocbRef)}  ${a.srcMac}`);
    });
    const live = !file;
    if (live) setInterval(() => engine.tick(Date.now()), 250);
    for await (const e of decode(file ? { file } : iface ? { iface } : { stdin: true })) engine.ingest(e);
    if (live) process.exit(0);
    if (!asJson) console.error(`${engine.alerts.length} alerts`);
    break;
  }
  case "replay": {
    const pcap = args[0];
    const iface = flag("--iface");
    const speed = Number(flag("--speed") ?? "1");
    if (!pcap || !iface || !(speed > 0)) usage();
    const pkts = readPcap(new Uint8Array(await Bun.file(pcap).arrayBuffer()));
    const sock = new RawSocket(iface);
    const start = performance.now();
    const t0 = pkts[0]?.tMs ?? 0;
    for (const p of pkts) {
      const due = (p.tMs - t0) / speed - (performance.now() - start);
      if (due > 1) await Bun.sleep(due);
      sock.send(retime(p.bytes, p.tMs, Date.now()));
    }
    sock.close();
    console.error(`replayed ${pkts.length} frames on ${iface} at ${speed}x`);
    break;
  }
  case "capture": {
    const iface = flag("--iface") ?? usage();
    const sock = new RawSocket(iface);
    const buf = new Uint8Array(65536);
    const out = Bun.stdout.writer();
    out.write(pcapHeader());
    out.flush();
    for (;;) {
      const n = sock.recv(buf);
      if (n <= 0) continue;
      out.write(pcapRecord({ tMs: Date.now(), bytes: buf.slice(0, n) }));
      out.flush();
    }
  }
  default:
    usage();
}
