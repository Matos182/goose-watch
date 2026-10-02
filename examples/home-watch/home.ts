// home-watch: the GOOSE Watch pattern for a home or small-office network, in one file.
//
//   rules (code)  decide every alert and its severity, from ARP traffic only
//   local AI      optional; gives a reading with honest doubt (below 0.60 it says "not sure")
//   human         decides; code says when a human must look, never the AI
//
// Passive: it only listens. There is no code path that sends a packet.
//
// usage:
//   bun home.ts demo [dir]                         write a demo capture + known.json, then watch it
//   bun home.ts learn <capture.pcap>               print a known.json from a capture of a normal day
//   bun home.ts watch (--file <pcap> | --iface <if>) --known known.json [--model nimble:latest] [--ollama http://127.0.0.1:11434]

import { mkdirSync } from "node:fs";
import { join } from "node:path";

// ---------- what a home network looks like on the wire ----------

export interface ArpEvent { tMs: number; op: 1 | 2; mac: string; ip: string; targetIp: string }

export interface Known {
  gateway: { ip: string; mac: string };
  devices: Record<string, string>; // mac -> a name you recognise ("kitchen tablet")
}

/** tshark is the decoder: the same fields from a file or a live interface. */
async function* arpEvents(src: { file?: string; iface?: string }): AsyncGenerator<ArpEvent> {
  const input = src.file ? ["-r", src.file, "-Y", "arp"] : ["-i", src.iface!, "-f", "arp", "-l"];
  const fields = ["frame.time_epoch", "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"];
  const p = Bun.spawn(["tshark", "-n", ...input, "-T", "fields", "-E", "separator=\t", ...fields.flatMap((f) => ["-e", f])], { stdout: "pipe", stderr: "ignore" });
  let buf = "";
  for await (const chunk of p.stdout) {
    buf += new TextDecoder().decode(chunk);
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const [t, op, mac, ip, target] = buf.slice(0, nl).split("\t");
      buf = buf.slice(nl + 1);
      if (!mac || !ip) continue;
      yield { tMs: Math.round(Number(t) * 1000), op: op === "2" ? 2 : 1, mac: mac.toLowerCase(), ip, targetIp: target ?? "" };
    }
  }
}

// ---------- the rules: the safety floor ----------

export type Rule = "NEW_DEVICE" | "ARP_SCAN" | "ROUTER_IMPERSONATION";
export const SEVERITY: Record<Rule, 1 | 2 | 3> = { NEW_DEVICE: 1, ARP_SCAN: 2, ROUTER_IMPERSONATION: 3 };
export const PLAIN: Record<Rule, string> = {
  NEW_DEVICE: "A device you have not listed joined the network.",
  ARP_SCAN: "One device asked for many addresses in a few seconds: someone is mapping your network.",
  ROUTER_IMPERSONATION: "A device that is not your router claims the router's address: traffic can be intercepted.",
};

export interface Alert { rule: Rule; severity: 1 | 2 | 3; mac: string; ip: string; tMs: number; facts: Record<string, unknown> }

const SCAN_WINDOW_MS = 10_000;
const SCAN_TARGETS = 20;

export class Rules {
  alerts: Alert[] = [];
  private seen = new Set<string>();
  private asked = new Map<string, { t: number; ip: string }[]>();
  private raised = new Set<string>();
  constructor(private known: Known) {}

  ingest(e: ArpEvent): Alert[] {
    const out: Alert[] = [];
    const raise = (rule: Rule, extra: Record<string, unknown> = {}) => {
      const key = `${rule}|${e.mac}`;
      if (this.raised.has(key)) return;
      this.raised.add(key);
      const a = { rule, severity: SEVERITY[rule], mac: e.mac, ip: e.ip, tMs: e.tMs, facts: this.facts(e, extra) };
      this.alerts.push(a);
      out.push(a);
    };
    if (!(e.mac in this.known.devices) && e.mac !== this.known.gateway.mac && !this.seen.has(e.mac)) raise("NEW_DEVICE");
    this.seen.add(e.mac);
    if (e.ip === this.known.gateway.ip && e.mac !== this.known.gateway.mac) raise("ROUTER_IMPERSONATION");
    if (e.op === 1 && e.targetIp) {
      const q = (this.asked.get(e.mac) ?? []).filter((x) => e.tMs - x.t < SCAN_WINDOW_MS);
      q.push({ t: e.tMs, ip: e.targetIp });
      this.asked.set(e.mac, q);
      const distinct = new Set(q.map((x) => x.ip)).size;
      if (distinct >= SCAN_TARGETS) raise("ARP_SCAN", { distinct_addresses_asked_in_10s: distinct });
    }
    return out;
  }

  /** Facts are measured here, never asked of a model. */
  private facts(e: ArpEvent, extra: Record<string, unknown>) {
    const first = parseInt(e.mac.slice(0, 2), 16);
    const hour = new Date(e.tMs).getHours();
    const q = (this.asked.get(e.mac) ?? []).filter((x) => e.tMs - x.t < SCAN_WINDOW_MS);
    return {
      device_is_in_your_list: e.mac in this.known.devices,
      mac_is_randomized_private_address: (first & 0x02) !== 0, // phones use these on Wi-Fi
      local_hour: hour,
      is_night: hour < 6,
      claims_the_router_address: e.ip === this.known.gateway.ip,
      distinct_addresses_asked_in_10s: new Set(q.map((x) => x.ip)).size,
      ...extra,
    };
  }
}

// ---------- the local AI: a reading with doubt, advisory only ----------

const CAUSES = {
  new_gadget_or_guest: "A new phone, laptop, TV or a guest's device joining normally.",
  own_device_new_address: "One of your own devices using a new private (randomized) address.",
  network_scan: "Something is mapping the network, by a person or by malware.",
  impersonation: "A device pretending to be another one, usually the router, to intercept traffic.",
  unclear: "The facts don't point to one of the above.",
} as const;
type Cause = keyof typeof CAUSES;
const SUSPICIOUS: Cause[] = ["network_scan", "impersonation"];
export const GATE = 0.6;

export interface Reading { cause: Cause; p: number }

async function aiReading(base: string, model: string, a: Alert): Promise<Reading | null> {
  if (!/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(base)) throw new Error("only a local model is allowed: nothing leaves the machine");
  try {
    const res = await fetch(`${base}/v1/systemone`, {
      method: "POST", headers: { "content-type": "application/json" }, redirect: "error", signal: AbortSignal.timeout(30_000),
      body: JSON.stringify({ model, state: { alert: a.rule, rule_meaning: PLAIN[a.rule], ...a.facts },
        questions: { cause: { type: "choice", instructions: "A home network monitor raised the alert in the state. What most likely happened?", criteria: CAUSES } } }),
    });
    const probs = (await res.json())?.answers?.cause?.probabilities as Record<string, number> | undefined;
    if (!probs || !Object.keys(CAUSES).every((k) => typeof probs[k] === "number")) return null;
    const [cause, p] = Object.entries(probs).reduce((x, y) => (y[1] > x[1] ? y : x)); // never trust the model's own "choice"
    return { cause: cause as Cause, p };
  } catch {
    return null;
  }
}

/** Whether a human must look now: decided in code. The AI can add a reason to look, never remove one. */
export function needsHuman(a: Alert, r: Reading | null): boolean {
  if (a.severity >= 2 || r === null) return true;
  return r.p < GATE || r.cause === "unclear" || SUSPICIOUS.includes(r.cause);
}

function show(a: Alert, r: Reading | null, aiOn: boolean) {
  const time = new Date(a.tMs).toTimeString().slice(0, 5);
  const ai = !aiOn ? "" : r === null ? "AI unavailable" : r.p < GATE || r.cause === "unclear"
    ? `AI not sure (best guess ${r.cause} ${r.p.toFixed(2)})` : `AI: ${r.cause} ${r.p.toFixed(2)}`;
  const human = needsHuman(a, aiOn ? r : null) ? "→ a human checks now" : "→ no action needed now";
  console.log(`${time}  [sev ${a.severity}] ${a.rule.padEnd(20)} ${a.mac} ${a.ip}\n        ${PLAIN[a.rule]}${ai ? `\n        ${ai}` : ""}\n        ${human}\n`);
}

// ---------- demo traffic and learning a baseline ----------

function arpFrame(op: 1 | 2, mac: string, ip: string, targetIp: string): Uint8Array {
  const m = (s: string) => s.split(":").map((h) => parseInt(h, 16));
  const v4 = (s: string) => s.split(".").map(Number);
  const f = [...(op === 1 ? [255, 255, 255, 255, 255, 255] : m("aa:aa:aa:00:00:10")), ...m(mac), 0x08, 0x06,
    0, 1, 8, 0, 6, 4, 0, op, ...m(mac), ...v4(ip), ...(op === 1 ? [0, 0, 0, 0, 0, 0] : m("aa:aa:aa:00:00:10")), ...v4(targetIp)];
  while (f.length < 60) f.push(0);
  return new Uint8Array(f);
}

export function writePcap(pkts: { tMs: number; bytes: Uint8Array }[]): Uint8Array {
  const out = new Uint8Array(24 + pkts.reduce((n, p) => n + 16 + p.bytes.length, 0));
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
  let o = 24;
  for (const p of pkts) {
    dv.setUint32(o, Math.floor(p.tMs / 1000), true); dv.setUint32(o + 4, (p.tMs % 1000) * 1000, true);
    dv.setUint32(o + 8, p.bytes.length, true); dv.setUint32(o + 12, p.bytes.length, true);
    out.set(p.bytes, o + 16); o += 16 + p.bytes.length;
  }
  return out;
}

export const DEMO_KNOWN: Known = {
  gateway: { ip: "192.168.1.1", mac: "aa:aa:aa:00:00:01" },
  devices: { "aa:aa:aa:00:00:10": "living-room laptop", "aa:aa:aa:00:00:20": "TV", "aa:aa:aa:00:00:30": "Home Assistant" },
};
export const DEMO_PHONE = "1a:2b:3c:4d:5e:6f"; // randomized private address (0x02 bit set)
export const DEMO_INTRUDER = "00:0c:29:13:37:42";

/** A quiet night at home, then: a phone with a private address, a scan, and a fake router. */
export function demoPackets(withIncidents = true) {
  const t0 = new Date(2026, 9, 3, 3, 0, 0).getTime(); // 03:00 local time
  const pkts: { tMs: number; bytes: Uint8Array }[] = [];
  const add = (sec: number, op: 1 | 2, mac: string, ip: string, target: string) => pkts.push({ tMs: t0 + Math.round(sec * 1000), bytes: arpFrame(op, mac, ip, target) });
  for (let s = 0; s < 1200; s += 60) {
    add(s, 1, "aa:aa:aa:00:00:10", "192.168.1.10", "192.168.1.1");
    add(s + 0.01, 2, "aa:aa:aa:00:00:01", "192.168.1.1", "192.168.1.10");
    add(s + 20, 1, "aa:aa:aa:00:00:20", "192.168.1.20", "192.168.1.1");
    add(s + 40, 1, "aa:aa:aa:00:00:30", "192.168.1.30", "192.168.1.1");
  }
  if (withIncidents) {
    add(12 * 60 + 5, 1, DEMO_PHONE, "192.168.1.57", "192.168.1.1"); // 03:12
    for (let i = 1; i <= 60; i++) add(14 * 60 + i * 0.08, 1, DEMO_INTRUDER, "192.168.1.66", `192.168.1.${i}`); // 03:14
    add(15 * 60, 2, DEMO_INTRUDER, "192.168.1.1", "192.168.1.10"); // 03:15, "I am the router"
  }
  return pkts.sort((a, b) => a.tMs - b.tMs);
}

async function watch(src: { file?: string; iface?: string }, known: Known, model: string | null, ollama: string) {
  const rules = new Rules(known);
  console.log(`watching ${src.file ?? src.iface} · ${Object.keys(known.devices).length} known devices · AI ${model ?? "off"} · passive, nothing is sent\n`);
  for await (const e of arpEvents(src)) for (const a of rules.ingest(e)) show(a, model ? await aiReading(ollama, model, a) : null, model !== null);
  return rules.alerts;
}

if (import.meta.main) {
  const [cmd, ...args] = Bun.argv.slice(2);
  const opt = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
  if (cmd === "demo") {
    const dir = args[0] && !args[0].startsWith("--") ? args[0] : "home-demo";
    mkdirSync(dir, { recursive: true });
    await Bun.write(join(dir, "night.pcap"), writePcap(demoPackets()));
    await Bun.write(join(dir, "known.json"), JSON.stringify(DEMO_KNOWN, null, 2) + "\n");
    await watch({ file: join(dir, "night.pcap") }, DEMO_KNOWN, opt("--model") ?? null, opt("--ollama") ?? "http://127.0.0.1:11434");
  } else if (cmd === "learn" && args[0]) {
    const devices: Record<string, string> = {};
    const ips = new Map<string, string>();
    for await (const e of arpEvents({ file: args[0] })) { devices[e.mac] = `device at ${e.ip}`; ips.set(e.ip, e.mac); }
    const gwIp = opt("--gateway") ?? "192.168.1.1";
    console.log(JSON.stringify({ gateway: { ip: gwIp, mac: ips.get(gwIp) ?? "set-me" }, devices }, null, 2));
  } else if (cmd === "watch" && (opt("--file") || opt("--iface")) && opt("--known")) {
    const known = (await Bun.file(opt("--known")!).json()) as Known;
    await watch({ file: opt("--file"), iface: opt("--iface") }, known, opt("--model") ?? null, opt("--ollama") ?? "http://127.0.0.1:11434");
  } else {
    console.error("usage: bun home.ts demo [dir] [--model m] | learn <pcap> [--gateway ip] | watch (--file f | --iface i) --known known.json [--model m] [--ollama url]");
    process.exit(2);
  }
}
