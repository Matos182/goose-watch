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
  pduTMs: number | null; // the PDU's own timestamp t
  stNum: number;
  sqNum: number;
  test: boolean;
  confRev: number;
  ndsCom: boolean;
  numDatSetEntries: number;
  // The dataset as compared by the rules: tshark's raw allData bytes (BER), so order, type and nesting all
  // count and every MMS type is covered. Only if tshark gives no raw bytes, the typed fields it decoded.
  values: string[];
}

const FIELDS = [
  "frame.time_epoch", "eth.src", "eth.dst", "vlan.id", "goose.appid", "goose.reserve1.s_bit",
  "goose.gocbRef", "goose.timeAllowedtoLive", "goose.datSet", "goose.goID", "goose.t", "goose.stNum", "goose.sqNum",
  "goose.simulation", "goose.confRev", "goose.ndsCom", "goose.numDatSetEntries",
  "goose.boolean", "goose.integer", "goose.unsigned", "goose.float_value", "goose.bit_string", "@goose.allData",
];

export type Source = { file: string } | { iface: string } | { stdin: true };

export function tsharkArgs(source: Source): string[] {
  const src = "file" in source ? ["-r", source.file] : "iface" in source ? ["-i", source.iface, "-l"] : ["-r", "-", "-l"];
  return [...src, "-Y", "goose", "-T", "ek", ...FIELDS.flatMap((f) => ["-e", f])];
}

const one = (l: Record<string, string[]>, k: string): string | undefined => l[k]?.[0];
const bool = (v: string | undefined) => v === "True" || v === "1";

// tshark prints t as "Sep 21, 2026 14:13:20.122999966 UTC".
export function parseGooseTime(v: string | undefined): number | null {
  const m = v?.match(/^(\w{3}) +(\d+), (\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? UTC$/);
  if (!m) return null;
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].indexOf(m[1]!);
  const ms = Math.round(Number(`0.${m[7] ?? "0"}`) * 1000);
  return Date.UTC(Number(m[3]), mon, Number(m[2]), Number(m[4]), Number(m[5]), Number(m[6])) + ms;
}

export function parseEkLine(line: string): GooseEvent | null {
  if (!line.startsWith('{"timestamp"')) return null;
  let l: Record<string, string[]>;
  try {
    l = (JSON.parse(line) as { layers: Record<string, string[]> }).layers;
  } catch {
    console.error(`decode: skipped an unreadable tshark line (${line.length} bytes)`);
    return null; // one broken line must not end a live capture
  }
  if (typeof l !== "object" || l === null) return null;
  const ref = one(l, "goose_gocbRef");
  // tshark only passes GOOSE frames (-Y goose). One whose PDU lost every field we read still has its
  // APPID header: it becomes an event, so MALFORMED_PDU reports it instead of it vanishing.
  if (ref === undefined && one(l, "goose_stNum") === undefined && one(l, "goose_appid") === undefined) return null;
  return {
    tMs: Math.round(Number(one(l, "frame_time_epoch")) * 1000),
    srcMac: one(l, "eth_src") ?? "",
    dstMac: one(l, "eth_dst") ?? "",
    vlanId: one(l, "vlan_id") === undefined ? null : Number(one(l, "vlan_id")),
    appId: parseInt(one(l, "goose_appid") ?? "", 16), // missing → NaN → MALFORMED_PDU, never an invented APPID 0
    simulationBit: bool(one(l, "goose_reserve1_s_bit")),
    gocbRef: ref ?? "", // a GOOSE PDU without gocbRef is reported as malformed, not dropped
    timeAllowedToLive: Number(one(l, "goose_timeAllowedtoLive")),
    datSet: one(l, "goose_datSet") ?? "",
    goID: one(l, "goose_goID") ?? "",
    pduTMs: parseGooseTime(one(l, "goose_t")),
    stNum: Number(one(l, "goose_stNum")),
    sqNum: Number(one(l, "goose_sqNum")),
    test: bool(one(l, "goose_simulation")),
    confRev: Number(one(l, "goose_confRev")),
    ndsCom: bool(one(l, "goose_ndsCom")),
    numDatSetEntries: Number(one(l, "goose_numDatSetEntries")),
    values: l["@goose_allData"] ?? [
      ...(l.goose_boolean ?? []), ...(l.goose_integer ?? []), ...(l.goose_unsigned ?? []),
      ...(l.goose_float_value ?? []), ...(l.goose_bit_string ?? []),
    ],
  };
}

export async function* decode(source: Source): AsyncGenerator<GooseEvent> {
  const proc = Bun.spawn(["tshark", ...tsharkArgs(source)], { stdin: "stdin" in source ? "inherit" : "ignore", stdout: "pipe", stderr: "pipe" });
  // Read stderr while capturing: on a long live run a full stderr pipe would stall tshark.
  let errTail = "";
  const drain = (async () => { for await (const chunk of proc.stderr.pipeThrough(new TextDecoderStream())) errTail = (errTail + chunk).slice(-300); })();
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
  await drain;
  if (code !== 0) throw new Error(`tshark exited ${code}: ${errTail}`);
}

export async function decodeAll(file: string): Promise<GooseEvent[]> {
  const out: GooseEvent[] = [];
  for await (const e of decode({ file })) out.push(e);
  return out;
}
