// SCL import (IEC 61850-6: SCD, CID, ICD): what the engineering file says should be on the bus.
// It gives each GOOSE control block its APPID, destination MAC, VLAN, dataset and member names, so a
// learned baseline can be checked against it and an alert can name the signal that changed.
// It never replaces `learn`: an SCD has no source MAC and no time-allowed-to-live, and the rules need both.

import { safeText, type Baseline } from "./rules";

export const MAX_SCL_BYTES = 64 * 1024 * 1024;

export interface SclBlock {
  gocbRef: string; // <LD domain>/LLN0$GO$<name>
  datSet: string; // <LD domain>/LLN0$<dataset name>
  confRev: number;
  goID: string; // GSEControl appID, which is the goID on the wire (not the APPID)
  members: string[]; // one per FCDA, in dataset order, which is the order of allData
  appId?: number; // from Communication/…/GSE/Address, hex in the file
  dstMac?: string; // lower case, colon separated
  vlanId?: number; // hex in the file
}

interface Node { name: string; attrs: Record<string, string>; children: Node[]; text: string }

const ENTITY: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function unescape(s: string): string {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z]+);|&/g, (m, ref: string | undefined) => {
    if (ref === undefined) throw new Error("SCL: stray '&'");
    if (ref.startsWith("#x")) return String.fromCodePoint(parseInt(ref.slice(2), 16));
    if (ref.startsWith("#")) return String.fromCodePoint(Number(ref.slice(1)));
    const v = ENTITY[ref];
    if (v === undefined) throw new Error(`SCL: unknown entity &${ref};`);
    return v;
  });
}

const local = (n: string) => n.slice(n.indexOf(":") + 1); // namespace prefixes do not matter here

/**
 * A small XML reader for SCL. It refuses what SCL never needs and an attacker would: a DOCTYPE, entity
 * declarations, entities other than the five predefined ones, and files over MAX_SCL_BYTES.
 */
export function parseXml(xml: string): Node {
  if (xml.length > MAX_SCL_BYTES) throw new Error("SCL: file too large");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("SCL: DOCTYPE and entity declarations are refused");
  const root: Node = { name: "#root", attrs: {}, children: [], text: "" };
  const stack = [root];
  const tag = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[A-Za-z_][\w:.-]*\s*=\s*(?:"[^"<]*"|'[^'<]*'))*)\s*(\/?)>/g;
  const attr = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let at = 0;
  for (let m: RegExpExecArray | null; (m = tag.exec(xml)); ) {
    const between = xml.slice(at, m.index);
    if (between.includes("<")) throw new Error(`SCL: malformed markup near byte ${at}`);
    stack.at(-1)!.text += unescape(between);
    at = tag.lastIndex;
    if (m[1] !== undefined) { stack.at(-1)!.text += m[1]; continue; }
    if (m[3] === undefined) continue; // comment or processing instruction
    const name = local(m[3]);
    if (m[2]) {
      const open = stack.pop();
      if (!open || open === root || open.name !== name) throw new Error(`SCL: unexpected </${name}>`);
      continue;
    }
    const attrs: Record<string, string> = {};
    for (const a of m[4]!.matchAll(attr)) attrs[local(a[1]!)] = unescape(a[2] ?? a[3] ?? "");
    const node: Node = { name, attrs, children: [], text: "" };
    stack.at(-1)!.children.push(node);
    if (!m[5]) stack.push(node);
  }
  if (xml.slice(at).includes("<")) throw new Error(`SCL: malformed markup near byte ${at}`);
  if (stack.length !== 1) throw new Error(`SCL: <${stack.at(-1)!.name}> is never closed`);
  return root;
}

const kids = (n: Node, name: string) => n.children.filter((c) => c.name === name);
const kid = (n: Node, name: string) => n.children.find((c) => c.name === name);

function hexInt(v: string | undefined): number | undefined {
  if (v === undefined || !/^\s*[0-9a-fA-F]{1,8}\s*$/.test(v)) return undefined;
  return parseInt(v, 16);
}

function mac(v: string | undefined): string | undefined {
  const m = v?.trim().toLowerCase().match(/^([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})$/);
  return m ? m.slice(1).join(":") : undefined;
}

/** "CTRL/XCBR1.Pos.stVal [ST]": the FCDA's logical device, node, data object and attribute. */
export function memberName(f: Record<string, string>): string {
  const ln = `${f.prefix ?? ""}${f.lnClass ?? ""}${f.lnInst ?? ""}`;
  const path = [ln, f.doName, f.daName].filter((p) => p !== undefined && p !== "").join(".");
  return `${f.ldInst ?? ""}/${path}${f.fc ? ` [${f.fc}]` : ""}`;
}

/** Every GOOSE control block in an SCL file, with its network address when the file has one. */
export function sclBlocks(xml: string): SclBlock[] {
  const scl = kid(parseXml(xml), "SCL");
  if (!scl) throw new Error("SCL: no <SCL> root element");

  const address = new Map<string, Record<string, string>>(); // ied|ldInst|cbName → P type → value
  for (const sub of kids(kid(scl, "Communication") ?? ({ children: [] } as unknown as Node), "SubNetwork"))
    for (const ap of kids(sub, "ConnectedAP"))
      for (const gse of kids(ap, "GSE")) {
        const p: Record<string, string> = {};
        for (const x of kids(kid(gse, "Address") ?? ({ children: [] } as unknown as Node), "P")) if (x.attrs.type) p[x.attrs.type] = x.text.trim();
        address.set(`${ap.attrs.iedName}|${gse.attrs.ldInst}|${gse.attrs.cbName}`, p);
      }

  const out: SclBlock[] = [];
  for (const ied of kids(scl, "IED"))
    for (const ap of kids(ied, "AccessPoint"))
      for (const server of kids(ap, "Server"))
        for (const ld of kids(server, "LDevice")) {
          const ln0 = kid(ld, "LN0");
          if (!ln0) continue;
          // The MMS domain is the IED name plus the LD inst, unless an Ed2 ldName replaces it.
          const domain = ld.attrs.ldName ?? `${ied.attrs.name ?? ""}${ld.attrs.inst ?? ""}`;
          const sets = new Map(kids(ln0, "DataSet").map((d) => [d.attrs.name, kids(d, "FCDA").map((f) => memberName(f.attrs))]));
          for (const gc of kids(ln0, "GSEControl")) {
            if (gc.attrs.type !== undefined && gc.attrs.type !== "GOOSE") continue; // GSSE is not GOOSE
            const p = address.get(`${ied.attrs.name}|${ld.attrs.inst}|${gc.attrs.name}`) ?? {};
            const b: SclBlock = {
              gocbRef: `${domain}/LLN0$GO$${gc.attrs.name ?? ""}`,
              datSet: `${domain}/LLN0$${gc.attrs.datSet ?? ""}`,
              confRev: Number(gc.attrs.confRev ?? "0"),
              goID: gc.attrs.appID ?? "",
              members: sets.get(gc.attrs.datSet) ?? [],
            };
            const appId = hexInt(p["APPID"]), dst = mac(p["MAC-Address"]), vlan = hexInt(p["VLAN-ID"]);
            if (appId !== undefined) b.appId = appId;
            if (dst !== undefined) b.dstMac = dst;
            if (vlan !== undefined) b.vlanId = vlan;
            out.push(b);
          }
        }
  return out.sort((a, b) => a.gocbRef.localeCompare(b.gocbRef));
}

export type Finding =
  | { kind: "not_in_scd"; gocbRef: string }
  | { kind: "not_on_wire"; gocbRef: string }
  | { kind: "mismatch"; gocbRef: string; field: "appId" | "datSet" | "confRev" | "numDatSetEntries" | "dstMac" | "vlanId"; wire: string; scd: string };

/**
 * Where the learned baseline (the wire) and the SCD (the design) disagree, and the baseline with
 * member names added from the SCD. Rule-relevant fields stay as learned: the SCD only names and reports.
 */
export function crossCheck(baseline: Baseline, blocks: SclBlock[]): { findings: Finding[]; baseline: Baseline } {
  const byRef = new Map(blocks.map((b) => [b.gocbRef, b]));
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const publishers = baseline.publishers.map((p) => {
    const ref = p.key.slice(p.key.indexOf("|") + 1);
    const b = byRef.get(ref);
    if (!b) { findings.push({ kind: "not_in_scd", gocbRef: ref }); return p; }
    seen.add(ref);
    const appId = parseInt(p.key.slice(0, p.key.indexOf("|")), 16);
    const hex = (n: number) => `0x${n.toString(16).padStart(4, "0")}`;
    const check = (field: Extract<Finding, { kind: "mismatch" }>["field"], wire: string | undefined, scd: string | undefined) => {
      if (wire !== undefined && scd !== undefined && wire !== scd) findings.push({ kind: "mismatch", gocbRef: ref, field, wire, scd });
    };
    check("appId", hex(appId), b.appId === undefined ? undefined : hex(b.appId));
    check("datSet", p.datSet, b.datSet);
    check("confRev", String(p.confRev), String(b.confRev));
    check("numDatSetEntries", String(p.numDatSetEntries), String(b.members.length));
    check("dstMac", p.dstMac?.toLowerCase(), b.dstMac);
    // An untagged frame and VLAN 0 (priority tag only) are the same VLAN.
    check("vlanId", p.vlanId === undefined ? undefined : String(p.vlanId ?? 0), b.vlanId === undefined ? undefined : String(b.vlanId));
    return b.members.length === p.numDatSetEntries ? { ...p, members: b.members } : p;
  });
  for (const b of blocks) if (!seen.has(b.gocbRef)) findings.push({ kind: "not_on_wire", gocbRef: b.gocbRef });
  return { findings, baseline: { ...baseline, publishers } };
}

/** One line per finding; every string from the file or the wire is escaped first. */
export function describe(f: Finding): string {
  const ref = safeText(f.gocbRef, 80);
  if (f.kind === "not_in_scd") return `on the wire, not in the SCD: ${ref}`;
  if (f.kind === "not_on_wire") return `in the SCD, not seen on the wire: ${ref}`;
  return `${ref}: ${f.field} is ${safeText(f.wire, 80)} on the wire, ${safeText(f.scd, 80)} in the SCD`;
}
