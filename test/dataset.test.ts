// C30: dataset values are compared in order and by type, through tshark's raw allData bytes.
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeAll } from "../src/decode";
import { encodeFrame, writePcap, type DataValue, type GooseFrame } from "../src/goose";
import { learn, RuleEngine } from "../src/rules";

const dir = mkdtempSync(join(tmpdir(), "goose-dataset-"));
const frame = (sqNum: number, allData: DataValue[]): GooseFrame => ({
  dstMac: "01:0c:cd:01:00:21", srcMac: "02:1e:d0:00:00:21", appId: 0x21, simulationBit: false,
  pdu: { gocbRef: "BAY9/LLN0$GO$gcbDs", timeAllowedToLive: 2000, datSet: "BAY9/LLN0$ds", goID: "BAY9", t: 0,
    stNum: 1, sqNum, test: false, confRev: 1, ndsCom: false, allData },
});

/** Two frames, same stNum, sqNum +1: the second changes only what `after` changes. */
async function classes(name: string, before: DataValue[], after: DataValue[]) {
  const file = join(dir, `${name}.pcap`);
  await Bun.write(file, writePcap([0, 1].map((i) => ({ tMs: 1_000 * (i + 1), bytes: encodeFrame(frame(i, i ? after : before)) }))));
  const events = await decodeAll(file);
  const engine = new RuleEngine(learn(events.slice(0, 1)));
  for (const e of events) engine.ingest(e);
  return engine.alerts.map((a) => a.cls);
}

const T: DataValue = { kind: "boolean", value: true };
const seven: DataValue = { kind: "integer", value: 7 };

describe("C30 the dataset is compared in order and by type", () => {
  test("an unchanged dataset raises nothing", async () => {
    expect(await classes("same", [T, seven], [T, seven])).toEqual([]);
  });
  test("swapping the order of two members is a change", async () => {
    expect(await classes("order", [T, seven], [seven, T])).toEqual(["DATA_WITHOUT_STNUM"]);
  });
  test("integer 7 becoming unsigned 7 is a change", async () => {
    expect(await classes("type", [T, seven], [T, { kind: "unsigned", value: 7 }])).toEqual(["DATA_WITHOUT_STNUM"]);
  });
  test("a change inside an octet string is a change", async () => {
    expect(await classes("octets", [{ kind: "octetString", value: [1, 2, 3] }], [{ kind: "octetString", value: [1, 2, 4] }])).toEqual(["DATA_WITHOUT_STNUM"]);
  });
});
