// Raw Ethernet send/receive through libc (AF_PACKET), for the isolated lab only.
// Guard (anti-claim A2): refuses to open any interface unless the current network
// namespace contains nothing but `lo` and lab links named gw*. A namespace with a
// real uplink (eth0, enp1s0, vmbr0, wlan0...) is refused, so lab GOOSE can never
// reach a production LAN.

import { dlopen, FFIType, ptr } from "bun:ffi";
import { existsSync, readdirSync } from "node:fs";

const AF_PACKET = 17;
const SOCK_RAW = 3;
const ETH_P_ALL = 0x0003;
const htons = (v: number) => ((v & 0xff) << 8) | ((v >> 8) & 0xff);

const libc = dlopen("libc.so.6", {
  socket: { args: [FFIType.i32, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  bind: { args: [FFIType.i32, FFIType.ptr, FFIType.u32], returns: FFIType.i32 },
  send: { args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32], returns: FFIType.i64 },
  recv: { args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32], returns: FFIType.i64 },
  if_nametoindex: { args: [FFIType.cstring], returns: FFIType.u32 },
  close: { args: [FFIType.i32], returns: FFIType.i32 },
});

export const LAB_IFACE = /^gw[a-z0-9]{1,8}$/;

// /sys/class/net can also hold plain files (e.g. bonding_masters); only entries with an ifindex are interfaces.
const liveInterfaces = () => readdirSync("/sys/class/net").filter((i) => existsSync(`/sys/class/net/${i}/ifindex`));

export function labNamespaceProblem(ifaces = liveInterfaces()): string | null {
  const foreign = ifaces.filter((i) => i !== "lo" && !LAB_IFACE.test(i));
  return foreign.length ? `network namespace has non-lab interfaces (${foreign.join(", ")}); run inside the lab namespace` : null;
}

/** The kernel's link type for an interface ("veth", "macvlan", ...), or null for a plain or unknown device. */
export function linkKind(iface: string): string | null {
  const r = Bun.spawnSync(["ip", "-d", "-j", "link", "show", "dev", iface]);
  if (r.exitCode !== 0) return null;
  return (JSON.parse(r.stdout.toString()) as { linkinfo?: { info_kind?: string } }[])[0]?.linkinfo?.info_kind ?? null;
}

// Only a veth is a lab link. A macvlan, ipvlan or VLAN named gw* sits on a real parent NIC, and a
// physical NIC renamed gw* has no link kind at all. What a veth's far end is plugged into is outside
// this namespace's view: the lab scripts never bridge it, and proxmox-lab.sh checks vmbr9 has no port.
export function labLinkProblem(iface: string, kind: string | null): string | null {
  return kind === "veth" ? null : `${iface} is ${kind ?? "a physical or unknown device"}, not a veth lab link`;
}

export class RawSocket {
  private fd: number;

  constructor(readonly iface: string) {
    if (!LAB_IFACE.test(iface)) throw new Error(`refusing interface ${JSON.stringify(iface)}: lab links must be named gw*`);
    const problem = labNamespaceProblem();
    if (problem) throw new Error(`refusing to open a raw socket: ${problem}`);
    const index = libc.symbols.if_nametoindex(Buffer.from(iface + "\0"));
    if (!index) throw new Error(`no such interface ${iface}`);
    const link = labLinkProblem(iface, linkKind(iface));
    if (link) throw new Error(`refusing to open a raw socket: ${link}`);
    this.fd = libc.symbols.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this.fd < 0) throw new Error("socket(AF_PACKET) failed: needs CAP_NET_RAW (run inside `unshare -rn`)");
    // struct sockaddr_ll: u16 family, be16 protocol, i32 ifindex, u16 hatype, u8 pkttype, u8 halen, u8 addr[8]
    const sll = new Uint8Array(20);
    const v = new DataView(sll.buffer);
    v.setUint16(0, AF_PACKET, true);
    v.setUint16(2, ETH_P_ALL, false);
    v.setInt32(4, index, true);
    if (libc.symbols.bind(this.fd, ptr(sll), 20) !== 0) throw new Error(`bind to ${iface} failed`);
  }

  send(frame: Uint8Array) {
    const n = Number(libc.symbols.send(this.fd, ptr(frame), frame.length, 0));
    if (n !== frame.length) throw new Error(`short send ${n}/${frame.length}`);
  }

  /** Blocking receive. Use it in a dedicated process. */
  recv(buf: Uint8Array): number {
    return Number(libc.symbols.recv(this.fd, ptr(buf), buf.length, 0));
  }

  close() {
    libc.symbols.close(this.fd);
  }
}
