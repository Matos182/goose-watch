import { expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeAll } from "../src/decode";
import { readT, retime, writePcap } from "../src/goose";
import { generate, SCENARIOS } from "../src/scenarios";

// Live replay sends recorded frames at a later wall-clock time. The receiver must measure the
// same PDU age (arrival − t) it would offline, or every live frame looks like a replay.
test("retime keeps every frame's PDU age and changes nothing else (tshark oracle)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "goose-retime-"));
  const story = SCENARIOS.find((s) => s.name === "story")!;
  const pkts = generate(story);
  const shift = 37 * 3600_000 + 123; // a day and a half later, odd ms
  const moved = pkts.map((p) => ({ tMs: p.tMs + shift, bytes: retime(p.bytes, p.tMs, p.tMs + shift) }));
  await Bun.write(join(dir, "a.pcap"), writePcap(pkts));
  await Bun.write(join(dir, "b.pcap"), writePcap(moved));
  const [a, b] = [await decodeAll(join(dir, "a.pcap")), await decodeAll(join(dir, "b.pcap"))];
  expect(b.length).toBe(a.length);
  let changed = 0;
  for (let i = 0; i < a.length; i++) {
    const [x, y] = [a[i]!, b[i]!];
    expect(Math.abs((y.tMs - y.pduTMs!) - (x.tMs - x.pduTMs!))).toBeLessThanOrEqual(1);
    const strip = (e: any) => ({ ...e, tMs: 0, pduTMs: 0 });
    expect(strip(y)).toEqual(strip(x));
    if (y.pduTMs !== x.pduTMs) changed++;
  }
  expect(changed).toBe(a.length);
});

test("readT returns null for a frame that is not GOOSE", () => {
  expect(readT(new Uint8Array(60))).toBeNull();
});
