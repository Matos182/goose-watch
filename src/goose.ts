// IEC 61850-8-1 GOOSE frame encoder (BER) and a classic pcap writer.
// Used only to build synthetic lab traffic; tshark is the independent decoder.

export type DataValue =
  | { kind: "boolean"; value: boolean }
  | { kind: "integer"; value: number }
  | { kind: "unsigned"; value: number }
  | { kind: "bitstring"; bits: number; value: number }
  | { kind: "float"; value: number }
  | { kind: "octetString"; value: number[] };

export interface GoosePdu {
  gocbRef: string;
  timeAllowedToLive: number; // ms
  datSet: string;
  goID: string;
  t: number; // ms since epoch
  stNum: number;
  sqNum: number;
  test: boolean; // "simulation" in Ed2, "test" in Ed1
  confRev: number;
  ndsCom: boolean;
  allData: DataValue[];
}

export interface GooseFrame {
  dstMac: string; // 01:0c:cd:01:xx:xx
  srcMac: string;
  vlanId?: number;
  vlanPriority?: number;
  appId: number;
  simulationBit: boolean; // Reserved1 bit 15 (Ed2 S bit)
  pdu: GoosePdu;
}

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  while (n > 0) {
    out.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return [0x80 | out.length, ...out];
}

function tlv(tag: number, value: number[]): number[] {
  return [tag, ...len(value.length), ...value];
}

// Minimal two's-complement encoding of a signed integer.
function intBytes(v: number): number[] {
  const out: number[] = [];
  let x = BigInt(Math.trunc(v));
  for (;;) {
    const byte = Number(x & 0xffn);
    out.unshift(byte);
    x >>= 8n;
    const signBit = (byte & 0x80) !== 0;
    if ((x === 0n && !signBit) || (x === -1n && signBit)) break;
  }
  return out;
}

const ascii = (s: string) => Array.from(new TextEncoder().encode(s));

// UtcTime: 4 bytes seconds, 3 bytes fraction of second, 1 byte quality.
function utcTime(ms: number): number[] {
  const secs = Math.floor(ms / 1000);
  const frac = Math.floor(((ms % 1000) / 1000) * 0x1000000);
  return [
    (secs >>> 24) & 0xff, (secs >>> 16) & 0xff, (secs >>> 8) & 0xff, secs & 0xff,
    (frac >>> 16) & 0xff, (frac >>> 8) & 0xff, frac & 0xff,
    0x0a, // quality: 10 bits of accuracy, clock synced
  ];
}

function data(d: DataValue): number[] {
  switch (d.kind) {
    case "boolean":
      return tlv(0x83, [d.value ? 0xff : 0x00]);
    case "integer":
      return tlv(0x85, intBytes(d.value));
    case "unsigned":
      return tlv(0x86, intBytes(d.value));
    case "bitstring": {
      const nBytes = Math.ceil(d.bits / 8);
      const unused = nBytes * 8 - d.bits;
      const bytes: number[] = [];
      for (let i = nBytes - 1; i >= 0; i--) bytes.push((d.value >>> (i * 8)) & 0xff);
      // MMS bit order: first bit is MSB of first byte.
      return tlv(0x84, [unused, ...bytes]);
    }
    case "float": {
      const b = new DataView(new ArrayBuffer(4));
      b.setFloat32(0, d.value);
      return tlv(0x87, [0x08, ...new Uint8Array(b.buffer)]);
    }
    case "octetString":
      return tlv(0x89, d.value);
  }
}

export function encodePdu(p: GoosePdu): number[] {
  const body = [
    ...tlv(0x80, ascii(p.gocbRef)),
    ...tlv(0x81, intBytes(p.timeAllowedToLive)),
    ...tlv(0x82, ascii(p.datSet)),
    ...tlv(0x83, ascii(p.goID)),
    ...tlv(0x84, utcTime(p.t)),
    ...tlv(0x85, intBytes(p.stNum)),
    ...tlv(0x86, intBytes(p.sqNum)),
    ...tlv(0x87, [p.test ? 0xff : 0x00]),
    ...tlv(0x88, intBytes(p.confRev)),
    ...tlv(0x89, [p.ndsCom ? 0xff : 0x00]),
    ...tlv(0x8a, intBytes(p.allData.length)),
    ...tlv(0xab, p.allData.flatMap(data)),
  ];
  return tlv(0x61, body);
}

const mac = (s: string) => s.split(":").map((h) => parseInt(h, 16));

export function encodeFrame(f: GooseFrame): Uint8Array {
  const pdu = encodePdu(f.pdu);
  const apduLen = 8 + pdu.length;
  const reserved1 = f.simulationBit ? 0x8000 : 0;
  const header = [
    ...mac(f.dstMac),
    ...mac(f.srcMac),
    ...(f.vlanId !== undefined
      ? [0x81, 0x00, (((f.vlanPriority ?? 4) << 5) | ((f.vlanId >> 8) & 0x0f)) & 0xff, f.vlanId & 0xff]
      : []),
    0x88, 0xb8,
    (f.appId >> 8) & 0xff, f.appId & 0xff,
    (apduLen >> 8) & 0xff, apduLen & 0xff,
    (reserved1 >> 8) & 0xff, reserved1 & 0xff,
    0x00, 0x00,
  ];
  const frame = [...header, ...pdu];
  while (frame.length < 60) frame.push(0); // Ethernet minimum, without FCS
  return new Uint8Array(frame);
}

export interface Packet {
  tMs: number;
  bytes: Uint8Array;
}

export function writePcap(packets: Packet[]): Uint8Array {
  const total = 24 + packets.reduce((n, p) => n + 16 + p.bytes.length, 0);
  const buf = new Uint8Array(total);
  const v = new DataView(buf.buffer);
  v.setUint32(0, 0xa1b2c3d4, true);
  v.setUint16(4, 2, true);
  v.setUint16(6, 4, true);
  v.setUint32(16, 65535, true);
  v.setUint32(20, 1, true); // LINKTYPE_ETHERNET
  let o = 24;
  for (const p of packets) {
    v.setUint32(o, Math.floor(p.tMs / 1000), true);
    v.setUint32(o + 4, Math.round((p.tMs % 1000) * 1000), true);
    v.setUint32(o + 8, p.bytes.length, true);
    v.setUint32(o + 12, p.bytes.length, true);
    buf.set(p.bytes, o + 16);
    o += 16 + p.bytes.length;
  }
  return buf;
}

export function readPcap(buf: Uint8Array): Packet[] {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (v.getUint32(0, true) !== 0xa1b2c3d4) throw new Error("not a little-endian microsecond pcap");
  const out: Packet[] = [];
  for (let o = 24; o + 16 <= buf.length; ) {
    const tMs = v.getUint32(o, true) * 1000 + v.getUint32(o + 4, true) / 1000;
    const n = v.getUint32(o + 8, true);
    out.push({ tMs, bytes: buf.slice(o + 16, o + 16 + n) });
    o += 16 + n;
  }
  return out;
}

export function pcapHeader(): Uint8Array {
  return writePcap([]);
}

export function pcapRecord(p: Packet): Uint8Array {
  return writePcap([p]).slice(24);
}

// Offset of the 8-byte UtcTime value (goosePdu tag 0x84) in an encoded frame, or -1.
function tOffset(b: Uint8Array): number {
  let i = 12;
  if (b[i] === 0x81 && b[i + 1] === 0x00) i += 4; // 802.1Q tag
  if (b[i] !== 0x88 || b[i + 1] !== 0xb8) return -1;
  i += 10; // ethertype, APPID, length, reserved1, reserved2
  if (b[i] !== 0x61) return -1;
  const lenAt = (j: number): [number, number] => {
    const l = b[j]!;
    if (l < 0x80) return [l, j + 1];
    let n = 0;
    for (let k = 1; k <= (l & 0x7f); k++) n = n * 256 + b[j + k]!;
    return [n, j + 1 + (l & 0x7f)];
  };
  let [, j] = lenAt(i + 1);
  while (j < b.length) {
    const tag = b[j]!;
    const [n, v] = lenAt(j + 1);
    if (tag === 0x84) return n === 8 ? v : -1;
    j = v + n;
  }
  return -1;
}

export function readT(b: Uint8Array): number | null {
  const o = tOffset(b);
  if (o < 0) return null;
  const secs = ((b[o]! << 24) >>> 0) + (b[o + 1]! << 16) + (b[o + 2]! << 8) + b[o + 3]!;
  const frac = (b[o + 4]! << 16) + (b[o + 5]! << 8) + b[o + 6]!;
  return secs * 1000 + Math.round((frac / 0x1000000) * 1000);
}

/**
 * Lab replay sends a recorded frame now, so its PDU timestamp is shifted by the same amount:
 * the age a receiver measures (arrival − t) stays what it was in the recording. Without this,
 * every replayed frame looks hours old, as if the whole stream were a replay attack.
 */
export function retime(b: Uint8Array, recordedMs: number, sendMs: number): Uint8Array {
  const o = tOffset(b);
  const t = readT(b);
  if (o < 0 || t === null) return b;
  const out = b.slice();
  out.set(utcTime(sendMs - (recordedMs - t)), o);
  return out;
}
