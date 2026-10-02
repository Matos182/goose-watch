// tshark is the decoder. We only read the fields we need, line by line (-T ek),
// so the same code serves a pcap file and a live interface.

export interface GooseEvent {
  tMs: number;
  srcMac: string;
  dstMac: string;
  vlanId: number | null;
  appId: number;
  simulationBit: boolean;
  gocbRef: string;
  timeAllowedToLive: number;
  datSet: string;
  goID: string;
  stNum: number;
  sqNum: number;
  test: boolean;
  confRev: number;
  ndsCom: boolean;
  numDatSetEntries: number;
  values: string[]; // booleans, integers, floats and bit strings in dataset order, as tshark prints them
}

const FIELDS = [
  "frame.time_epoch", "eth.src", "eth.dst", "vlan.id", "goose.appid", "goose.reserve1.s_bit",
  "goose.gocbRef", "goose.timeAllowedtoLive", "goose.datSet", "goose.goID", "goose.stNum", "goose.sqNum",
  "goose.simulation", "goose.confRev", "goose.ndsCom", "goose.numDatSetEntries",
  "goose.boolean", "goose.integer", "goose.unsigned", "goose.float_value", "goose.bit_string",
];

export function tsharkArgs(source: { file: string } | { iface: string }): string[] {
  const src = "file" in source ? ["-r", source.file] : ["-i", source.iface, "-l"];
  return [...src, "-Y", "goose", "-T", "ek", ...FIELDS.flatMap((f) => ["-e", f])];
}

const one = (l: Record<string, string[]>, k: string): string | undefined => l[k]?.[0];
const bool = (v: string | undefined) => v === "True" || v === "1";

export function parseEkLine(line: string): GooseEvent | null {
  if (!line.startsWith('{"timestamp"')) return null;
  const l = (JSON.parse(line) as { layers: Record<string, string[]> }).layers;
  const ref = one(l, "goose_gocbRef");
  if (ref === undefined) return null;
  return {
    tMs: Math.round(Number(one(l, "frame_time_epoch")) * 1000),
    srcMac: one(l, "eth_src") ?? "",
    dstMac: one(l, "eth_dst") ?? "",
    vlanId: one(l, "vlan_id") === undefined ? null : Number(one(l, "vlan_id")),
    appId: parseInt(one(l, "goose_appid") ?? "0", 16),
    simulationBit: bool(one(l, "goose_reserve1_s_bit")),
    gocbRef: ref,
    timeAllowedToLive: Number(one(l, "goose_timeAllowedtoLive")),
    datSet: one(l, "goose_datSet") ?? "",
    goID: one(l, "goose_goID") ?? "",
    stNum: Number(one(l, "goose_stNum")),
    sqNum: Number(one(l, "goose_sqNum")),
    test: bool(one(l, "goose_simulation")),
    confRev: Number(one(l, "goose_confRev")),
    ndsCom: bool(one(l, "goose_ndsCom")),
    numDatSetEntries: Number(one(l, "goose_numDatSetEntries")),
    values: [
      ...(l.goose_boolean ?? []), ...(l.goose_integer ?? []), ...(l.goose_unsigned ?? []),
      ...(l.goose_float_value ?? []), ...(l.goose_bit_string ?? []),
    ],
  };
}

export async function* decode(source: { file: string } | { iface: string }): AsyncGenerator<GooseEvent> {
  const proc = Bun.spawn(["tshark", ...tsharkArgs(source)], { stdout: "pipe", stderr: "pipe" });
  const reader = proc.stdout.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const ev = parseEkLine(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      if (ev) yield ev;
    }
  }
  const code = await proc.exited;
  if (code !== 0) throw new Error(`tshark exited ${code}: ${(await new Response(proc.stderr).text()).slice(0, 300)}`);
}

export async function decodeAll(file: string): Promise<GooseEvent[]> {
  const out: GooseEvent[] = [];
  for await (const e of decode({ file })) out.push(e);
  return out;
}
