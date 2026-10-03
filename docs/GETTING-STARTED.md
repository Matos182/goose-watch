# Getting started

This guide takes you from a fresh clone to a live board with a local AI, and then shows how to point the pattern at your own network. Each step works on its own, so you can stop at any level.

You need Linux or WSL2. Nothing here touches a real network until step 4, and even then it only listens.

## 0 · Install

| Tool | Version | What it does here |
|---|---|---|
| [bun](https://bun.sh) | ≥ 1.4 | runs everything (TypeScript, no build step) |
| `tshark` (Wireshark) | ≥ 4.4 | the GOOSE decoder; the tests also use it as the oracle |
| [Ollama](https://ollama.com) | ≥ 0.35 | optional: serves the local decision model on `/v1/systemone` |

```sh
git clone https://github.com/Matos182/goose-watch && cd goose-watch
bun install
bun test            # 76 tests; every scenario is decoded by tshark and checked against the rules
```

## 1 · Offline: rules on a capture file

The repository ships one synthetic pcap per attack or fault. The rules need a **baseline**, which is the list of publishers that are normal on this bus, learned from a clean capture.

```sh
bun src/cli.ts learn fixtures/baseline.pcap my-baseline.json   # learn what "normal" looks like
bun src/cli.ts run --file fixtures/replay.pcap --baseline my-baseline.json
# 1 alerts
# ...  sev 3  STNUM_REGRESSION   BAY1_CTRL/LLN0$GO$gcbPos  02:1e:d0:00:00:11
```

Try the other files in `fixtures/` (`poisoning`, `spoofed-mac`, `ttl-expiry`, …). `bun src/cli.ts scenarios fixtures` regenerates all of them, byte for byte.

## 2 · Live: an isolated lab and the board

The lab runs in a private network namespace with one virtual cable (`gwa` → `gwb`) and no way out. One side replays a scenario and the other side captures it, so the rules see real frames on a real interface.

```sh
scripts/lab.sh replay 4                  # one scenario at 4x; alerts land in reports/live/replay.alerts.jsonl
scripts/demo.sh 2                        # loops a story with every kind of event, board on http://127.0.0.1:8099
scripts/demo.sh stop
```

Without a model, every alert still appears with its severity, and the AI column says **"AI unavailable: a human checks now"**. That is on purpose: the rules never wait for the AI.

If `unshare -rnm` is refused, your distribution restricts unprivileged user namespaces. Check its documentation before you change that setting.

## 3 · Add the local AI

```sh
ollama pull nimble          # 9B, best on a GPU; tev1 (4B) and tev1:0.8b run on CPU
scripts/demo.sh 2           # the board now asks nimble about each alert
```

Each reading gives a cause (cyberattack, maintenance, device fault or unclear) with its probability. Below 0.60 the board says **not sure**. Who has to look is decided in code, not by the model: severity 2 or 3, an unsure model or an attack reading means a human checks now.

The board talks only to a loopback Ollama. Any other address is refused, so captures never leave the machine. You can run several models side by side, one server each: `GW_BOARD_ARGS="--models nimble:latest,tev1:latest@http://127.0.0.1:11436" scripts/demo.sh 2`.

To measure a model before you trust it, run it on the held-out gold set:

```sh
bun src/eval.ts nimble:latest --gold gold/gold-v3.json --pack 3
```

`docs/EVAL.md` explains the stop rule, which was fixed before any model ran.

## 4 · Your own network

- **A real GOOSE bus:** connect to a switch mirror port and learn a baseline from a capture you know is clean. Then run `bun src/cli.ts run --iface <if> --baseline <file>`. `tshark` only listens; capturing needs the usual Wireshark permissions.
- **A home or small office:** `examples/home-watch/` is the same pattern for ARP (new device, network scan, fake router) in one file. `bun examples/home-watch/home.ts demo` runs it with no network access.
- **Anything else:** `docs/PATTERN.md` turns the idea into a recipe (rules, measured facts, honest doubt, a human) with examples for smart homes, solar plants and servers.

## 5 · Read the code

Read the modules in the order the data flows. Each file opens with a comment saying what it does and what it must never do.

| Order | File | Read it for |
|---|---|---|
| 1 | `src/goose.ts` | how a GOOSE frame is built (BER encoding) and written to pcap |
| 2 | `src/scenarios.ts` | how each attack and fault is simulated, seeded so it's reproducible |
| 3 | `src/decode.ts` | how `tshark` turns frames into events, from a file or a live interface |
| 4 | `src/rules.ts` | **the safety floor:** every alert class, its severity and its plain-language text |
| 5 | `src/triage.ts` | how the model is asked (pack 1), validated, and kept from deciding who looks |
| 6 | `src/hops.ts` | packs 2 and 3: facts measured in code, the model picks a pattern, code maps it to a cause |
| 7 | `src/board.ts`, `src/board.html` | the live page |
| 8 | `src/rawsock.ts` | the guard that keeps lab frames off any real network |

### Add a rule

1. Add the class to `AlertClass`, `RULE_SEVERITY` and `RULE_TEXT` in `src/rules.ts`, then raise it in `RuleEngine.ingest`.
2. Add a scenario that triggers it in `src/scenarios.ts`, with its expected alert set.
3. Run `bun test`, then `scripts/mutate-rules.sh` after adding your class to its list. The mutation script removes each rule in turn and checks that a test fails, which proves that each rule is really covered.

The model never needs to change when you add a rule. It only explains the alerts the rules raise.
