#!/usr/bin/env bun
// The board: tails the lab's alert stream, asks local System One models for their
// reading, and serves a live page on loopback. Rules decide; models only comment.
// usage: bun src/board.ts [--alerts reports/live/board.jsonl] [--port 8099] [--models nimble:latest,tev1:0.8b@http://127.0.0.1:11436] [--base http://127.0.0.1:11434]

import { existsSync, statSync, openSync, readSync, closeSync } from "node:fs";
import type { Alert } from "./rules";
import { RULE_TEXT, safeText } from "./rules";
import { STOP_RULE } from "./eval";
import { SystemOneAdapter, verdict, type TriageResult } from "./triage";
import { triage2, triage3 } from "./hops";

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

// One model call at a time keeps the GPU predictable during a live demo.
let queue = Promise.resolve();
function onAlert(a: Alert) {
  const item: Item = { id: nextId++, alert: { ...a, gocbRef: safeText(a.gocbRef, 80) }, plain: RULE_TEXT[a.cls], readings: [] };
  items.push(item);
  if (items.length > 200) items = items.slice(-200);
  broadcast("alert", item);
  for (const [i, ad] of adapters.entries()) {
    queue = queue.then(async () => {
      const rd = reading(models[i]!, a, pack === "3" ? await triage3(ad, a) : pack === "2" ? await triage2(ad, a) : await ad.triage(a, a.context));
      item.readings.push(rd);
      broadcast("reading", { id: item.id, reading: rd });
    });
  }
}

// Tail the JSONL the lab writes. A {"reset":true} line starts a new story loop.
let offset = existsSync(file) ? statSync(file).size : 0;
let partial = "";
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
  for (const l of lines) {
    if (!l.trim()) continue;
    const o = JSON.parse(l);
    if (o.reset) { items = []; broadcast("reset", {}); continue; }
    onAlert(o as Alert);
  }
}, 200);

Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch(req) {
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
