// C33: the live path — frame clock for piped captures, unreadable tshark lines, stderr drained.
import { describe, expect, test } from "bun:test";
import { frameClock } from "../src/clock";
import { CAPTURE_FILTER, parseEkLine, tsharkArgs } from "../src/decode";

describe("C33 the live path", () => {
  test("the frame clock runs from the last frame, not from the wall", () => {
    let wall = 5_000_000;
    const c = frameClock(() => wall);
    expect(c.now()).toBeNull();
    c.saw(1_000);
    wall += 250;
    expect(c.now()).toBe(1_250);
  });
  test("an unreadable tshark line is skipped, not thrown", () => {
    expect(parseEkLine('{"timestamp":"1","layers":{"goose_stNum":["1"')).toBeNull();
  });
  test("an old capture piped to run --stdin raises the same alerts as run --file", async () => {
    const args = ["src/cli.ts", "run", "--baseline", "fixtures/baseline.json", "--json"];
    const classes = (out: string) => out.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((a) => a.cls).map((a) => a.cls).sort();
    const byFile = await new Response(Bun.spawn(["bun", ...args, "--file", "fixtures/replay.pcap"], { stdout: "pipe", stderr: "ignore" }).stdout).text();
    // A shell pipe held open for a second after the capture, as a live pipe would be, so the timer
    // ticks. (A Bun "pipe" is a socket, which tshark refuses to read.)
    const piped = Bun.spawn(["bash", "-c", `(cat fixtures/replay.pcap; sleep 1) | bun ${args.join(" ")} --stdin`], { stdout: "pipe", stderr: "ignore" });
    const byStdin = await new Response(piped.stdout).text();
    expect(await piped.exited).toBe(0);
    expect(classes(byStdin)).toEqual(classes(byFile)); // no TTL_EXPIRY from comparing 2026-10-01 frames to today's wall clock
  }, 30_000);
});

describe("C36 the kernel capture filter", () => {
  test("a live interface gets the GOOSE capture filter, tagged and untagged", () => {
    const a = tsharkArgs({ iface: "eth1" });
    expect(a.slice(a.indexOf("-f"), a.indexOf("-f") + 2)).toEqual(["-f", CAPTURE_FILTER]);
    expect(CAPTURE_FILTER).toBe("ether proto 0x88b8 or (vlan and ether proto 0x88b8)");
  });

  test("files and stdin take no capture filter (tshark refuses -f with -r)", () => {
    expect(tsharkArgs({ file: "x.pcap" })).not.toContain("-f");
    expect(tsharkArgs({ stdin: true })).not.toContain("-f");
  });
});
