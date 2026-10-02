import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEMO_INTRUDER, DEMO_KNOWN, DEMO_PHONE, demoPackets, needsHuman, Rules, writePcap, type Alert, type ArpEvent } from "../examples/home-watch/home";

// tshark is the oracle: decode the demo capture exactly as `watch --file` does.
async function decode(pkts: ReturnType<typeof demoPackets>): Promise<ArpEvent[]> {
  const f = join(mkdtempSync(join(tmpdir(), "home-")), "c.pcap");
  await Bun.write(f, writePcap(pkts));
  const out = await new Response(Bun.spawn(["tshark", "-n", "-r", f, "-Y", "arp", "-T", "fields", "-E", "separator=\t",
    "-e", "frame.time_epoch", "-e", "arp.opcode", "-e", "arp.src.hw_mac", "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4"]).stdout).text();
  return out.trim().split("\n").map((l) => { const [t, op, mac, ip, target] = l.split("\t");
    return { tMs: Math.round(Number(t) * 1000), op: op === "2" ? 2 : 1, mac: mac!, ip: ip!, targetIp: target! } as ArpEvent; });
}
const run = (evs: ArpEvent[], known = DEMO_KNOWN) => { const r = new Rules(known); evs.forEach((e) => r.ingest(e)); return r.alerts; };
const sig = (as: Alert[]) => as.map((a) => `${a.rule}@${a.mac}`).sort();

test("every demo frame decodes through tshark", async () => {
  expect((await decode(demoPackets())).length).toBe(demoPackets().length);
});

test("the demo night raises exactly its 4 alerts; a quiet night raises none", async () => {
  expect(sig(run(await decode(demoPackets())))).toEqual(
    [`ARP_SCAN@${DEMO_INTRUDER}`, `NEW_DEVICE@${DEMO_INTRUDER}`, `NEW_DEVICE@${DEMO_PHONE}`, `ROUTER_IMPERSONATION@${DEMO_INTRUDER}`].sort());
  expect(run(await decode(demoPackets(false)))).toEqual([]);
});

test("negative controls: listing the phone silences it; the real router never impersonates itself", async () => {
  const evs = await decode(demoPackets());
  const known = { ...DEMO_KNOWN, devices: { ...DEMO_KNOWN.devices, [DEMO_PHONE]: "my phone" } };
  expect(sig(run(evs, known))).not.toContain(`NEW_DEVICE@${DEMO_PHONE}`);
  expect(run(evs).filter((a) => a.rule === "ROUTER_IMPERSONATION").every((a) => a.mac !== DEMO_KNOWN.gateway.mac)).toBe(true);
});

test("severity 2 and 3 always need a human, whatever the AI says", () => {
  for (const severity of [1, 2, 3] as const) for (const cause of ["new_gadget_or_guest", "impersonation", "unclear"] as const) for (const p of [0.3, 0.99]) {
    const a = { rule: "NEW_DEVICE", severity, mac: "", ip: "", tMs: 0, facts: {} } as Alert;
    if (severity >= 2) expect(needsHuman(a, { cause, p })).toBe(true);
  }
  const a1 = { rule: "NEW_DEVICE", severity: 1, mac: "", ip: "", tMs: 0, facts: {} } as Alert;
  expect(needsHuman(a1, { cause: "new_gadget_or_guest", p: 0.9 })).toBe(false);
  expect(needsHuman(a1, null)).toBe(true);
});

test("passive by construction: the example has no code that sends packets", () => {
  const src = readFileSync(join(import.meta.dir, "../examples/home-watch/home.ts"), "utf8");
  expect(src).not.toMatch(/AF_PACKET|socket\(|sendto|\.send\(|tcpreplay|scapy/);
});
