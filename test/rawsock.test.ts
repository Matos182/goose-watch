import { describe, expect, test } from "bun:test";
import { labLinkProblem, labNamespaceProblem, RawSocket } from "../src/rawsock";

describe("A2 lab frames never reach a real network", () => {
  test("refuses interfaces not named gw*", () => {
    for (const i of ["eth0", "enp1s0", "vmbr0", "wlp2s0", "gw", "gw0;rm"]) expect(() => new RawSocket(i)).toThrow(/refusing/);
  });
  test("refuses a namespace that has any non-lab interface", () => {
    expect(labNamespaceProblem(["lo", "gwa", "gwb"])).toBeNull();
    expect(labNamespaceProblem(["lo", "gwa", "eth0"])).toMatch(/eth0/);
    expect(labNamespaceProblem(["lo", "gwa", "enp1s0", "wlp2s0"])).toMatch(/enp1s0/);
  });
  test("refuses even a gw* name on this host namespace (it has a real uplink)", () => {
    expect(() => new RawSocket("gwa")).toThrow(/non-lab interfaces/);
  });
});

describe("A2 interface listing", () => {
  test("non-interface files in /sys/class/net are ignored, real ones still refused", () => {
    expect(labNamespaceProblem(["lo", "gw0"])).toBeNull();
  });
});

describe("A2 only a veth is a lab link", () => {
  test("a gw* name on a macvlan, VLAN, bridge or renamed physical NIC is refused", () => {
    expect(labLinkProblem("gwa", "veth")).toBeNull();
    for (const kind of ["macvlan", "ipvlan", "vlan", "bridge", "macvtap", null]) expect(labLinkProblem("gw0", kind)).toMatch(/not a veth/);
  });
});
