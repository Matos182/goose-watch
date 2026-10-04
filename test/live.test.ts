// C33: the live path — frame clock for piped captures, unreadable tshark lines, stderr drained.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

// A child bun runs decode() against a stand-in tshark that prints one frame and never exits, like a
// live capture on a quiet bus. (A real `tshark -r -` happens to die with its parent here, so it cannot
// show the leak; a real `tshark -i` did not, on the lab laptop.) The tests stop the child and look for
// the tshark it started.
describe("C37 tshark never outlives the monitor", () => {
  const tsharkChildren = (pid: number) =>
    Bun.spawnSync(["pgrep", "-P", String(pid), "-x", "tshark"]).stdout.toString().trim().split("\n").filter(Boolean).map(Number);
  const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const waitFor = async (ok: () => boolean, ms = 5000) => { const end = Date.now() + ms; while (!ok() && Date.now() < end) await Bun.sleep(50); return ok(); };

  const fakeDir = mkdtempSync(join(tmpdir(), "gw-fake-tshark-"));
  writeFileSync(join(fakeDir, "tshark"), "#!/bin/bash\ntrap '' PIPE\necho '{\"timestamp\":\"0\",\"layers\":{\"goose_appid\":[\"0x0001\"]}}'\nwhile :; do sleep 0.1; done\n", { mode: 0o755 });
  afterAll(() => rmSync(fakeDir, { recursive: true, force: true }));

  async function startChild(code: string) {
    const child = Bun.spawn(["bun", "-e", code], {
      cwd: `${import.meta.dir}/..`, stdin: "pipe", stdout: "pipe", stderr: "ignore",
      env: { ...process.env, PATH: `${fakeDir}:${process.env.PATH}` },
    });
    expect(await waitFor(() => tsharkChildren(child.pid).length === 1)).toBe(true);
    return { child, tshark: tsharkChildren(child.pid)[0]! };
  }

  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    test(`${sig} to the monitor stops its tshark`, async () => {
      const { child, tshark } = await startChild(`import { decode } from "./src/decode"; for await (const e of decode({ stdin: true })) {}`);
      child.kill(sig);
      await child.exited;
      expect(await waitFor(() => !alive(tshark))).toBe(true);
    });
  }

  test("a caller that stops reading early stops tshark", async () => {
    const { child, tshark } = await startChild(
      `import { decode } from "./src/decode"; for await (const e of decode({ iface: "gw0" })) { await Bun.sleep(1000); break; } await Bun.sleep(5000);`);
    expect(await waitFor(() => !alive(tshark))).toBe(true);
    expect(alive(child.pid)).toBe(true); // the monitor itself is still running
    child.kill();
  });
});
