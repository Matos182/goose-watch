#!/usr/bin/env bun
// The board: tails the lab's alert stream, asks local System One models for their
// reading, and serves a live page on loopback. Rules decide; models only comment.
// usage: bun src/board.ts [--alerts reports/live/board.jsonl] [--port 8099] [--models nimble:latest,tev1:0.8b@http://127.0.0.1:11436] [--base http://127.0.0.1:11434]

import { existsSync, statSync, openSync, readSync, closeSync, readFileSync } from "node:fs";
import type { Alert } from "./rules";
import { RULE_TEXT, safeText } from "./rules";
import { STOP_RULE } from "./eval";
import { SystemOneAdapter, verdict, type TriageResult } from "./triage";
import { triage2, triage3 } from "./hops";
import { Backlog } from "./backlog";
import type { AlertUpdate } from "./updates";

const args = Bun.argv.slice(2);
const opt = (n: string, d: string) => (args.includes(n) ? args[args.indexOf(n) + 1]! : d);
const file = opt("--alerts", "reports/live/board.jsonl");
const port = Number(opt("--port", "8099"));
const base = opt("--base", "http://127.0.0.1:11434"); // a stock `ollama serve`
// model@base lets each model live on its own server (e.g. nimble on the GPU, tev1 on a CPU-only Ollama),
// so two models that don't fit in VRAM together never evict each other mid-demo.
const specs = opt("--models", "nimble:latest").split(",");
const models = specs.map((m) => m.split("@")[0]!);
const pack = opt("--pack", "3");
const adapters = specs.map((m) => new SystemOneAdapter(m.split("@")[1] ?? base, m.split("@")[0]!, 30_000));

interface Reading { model: string; text: string; notSure: boolean; cause?: string; p?: number; human?: boolean; dist?: Record<string, number> }
interface Item { id: number; alert: Alert; plain: string; readings: Reading[] }

let items: Item[] = [];
let nextId = 1;
const clients = new Set<ReadableStreamDefaultController>();
const enc = new TextEncoder();

function broadcast(event: string, data: unknown) {
  const msg = enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  for (const c of clients) {
    try { c.enqueue(msg); } catch { clients.delete(c); }
  }
}

function reading(model: string, a: Alert, r: TriageResult): Reading {
  const v = verdict(a, r, STOP_RULE.gate);
  if (!r.ok) return { model, text: v.ai, notSure: true };
  return { model, text: v.ai, notSure: v.notSure, cause: r.triage.causeWinner, p: r.triage.causeP, human: v.human, dist: r.triage.cause };
}

// One model call at a time keeps the GPU predictable during a live demo; the backlog is capped.
const backlog = new Backlog();
function onAlert(a: Alert, ask = true) {
  const item: Item = { id: nextId++, alert: { ...a, gocbRef: safeText(a.gocbRef, 80) }, plain: RULE_TEXT[a.cls], readings: [] };
  items.push(item);
  if (items.length > 200) items = items.slice(-200);
  broadcast("alert", item);
  const post = (rd: Reading) => { item.readings.push(rd); broadcast("reading", { id: item.id, reading: rd }); };
  // Alerts from before the board started are shown again, but not sent to the models.
  if (!ask) for (const m of models) post({ model: m, text: "AI not asked (alert from before the board started)", notSure: true });
  else for (const [i, ad] of adapters.entries()) {
    backlog.run(
      async () => {
        try {
          post(reading(models[i]!, a, pack === "3" ? await triage3(ad, a) : pack === "2" ? await triage2(ad, a) : await ad.triage(a, a.context)));
        } catch (e) {
          post({ model: models[i]!, text: `AI error (${(e as Error).name}): a human checks now`, notSure: true });
        }
      },
      () => post({ model: models[i]!, text: "AI skipped (alert backlog): a human checks now", notSure: true }),
    );
  }
}

/** A repeat of an open alert: update its count on the card. */
function onUpdate(u: AlertUpdate) {
  const it = items.find((x) => x.alert.cls === u.update.cls && x.alert.key === u.update.key && x.alert.tMs === u.update.tMs);
  if (!it) return;
  it.alert.count = u.count;
  it.alert.lastMs = u.lastMs;
  broadcast("update", { id: it.id, count: u.count, lastMs: u.lastMs });
}

function handle(l: string, live: boolean) {
  if (!l.trim()) return;
  let o: any;
  try { o = JSON.parse(l); } catch { console.error(`board: skipped a malformed alert line (${l.length} bytes)`); return; }
  if (o.reset) { items = []; broadcast("reset", {}); return; }
  if (o.update) { onUpdate(o as AlertUpdate); return; }
  onAlert(o as Alert, live);
}

// On start, show the current run again (everything after the last {"reset":true}, up to the last
// 200 lines), so a restarted board does not hide a condition that is still open. Then tail the file.
let offset = 0;
let partial = "";
if (existsSync(file)) {
  const text = readFileSync(file, "utf8");
  offset = Buffer.byteLength(text);
  const lines = text.split("\n");
  const lastReset = lines.findLastIndex((l) => l.includes('"reset":true'));
  for (const l of lines.slice(lastReset + 1).slice(-200)) handle(l, false);
}
setInterval(() => {
  if (!existsSync(file)) return;
  const size = statSync(file).size;
  if (size < offset) offset = 0;
  if (size === offset) return;
  const fd = openSync(file, "r");
  const buf = Buffer.alloc(size - offset);
  readSync(fd, buf, 0, buf.length, offset);
  closeSync(fd);
  offset = size;
  partial += buf.toString("utf8");
  const lines = partial.split("\n");
  partial = lines.pop()!;
  for (const l of lines) handle(l, true);
}, 200);

const ALLOWED_HOSTS = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);

Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch(req) {
    // Loopback alone does not stop a DNS-rebinding page in the browser: answer only our own host name.
    if (!ALLOWED_HOSTS.has(req.headers.get("host") ?? "")) return new Response("forbidden", { status: 403 });
    const url = new URL(req.url);
    if (url.pathname === "/events") {
      let ctl: ReadableStreamDefaultController;
      return new Response(new ReadableStream({
        start(c) { ctl = c; clients.add(c); c.enqueue(enc.encode(`event: snapshot\ndata: ${JSON.stringify({ items, models })}\n\n`)); },
        cancel() { clients.delete(ctl); },
      }), { headers: { "content-type": "text/event-stream", "cache-control": "no-cache" } });
    }
    if (url.pathname === "/") return new Response(Bun.file(new URL("./board.html", import.meta.url)));
    return new Response("not found", { status: 404 });
  },
});
console.log(`board on http://127.0.0.1:${port} · pack ${pack} · models ${specs.join(", ")} · tailing ${file}`);
