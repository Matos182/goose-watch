# Model evaluation: classes, gold set and stop rule

Fixed on 2026-10-02, **before the first model run** (claim C7 in [CLAIMS.md](CLAIMS.md)). Changing anything here after a run needs a new held-out gold set (seeds ≥ 300), never a re-run on this one.

## What the model is asked

Pack `triage-pack-1` (`src/triage.ts`) asks three questions about one alert:

- **cause** (Choice): `cyberattack` · `maintenance` · `device_fault` · `unclear`. The descriptions in the code are written so that no two of them cover the same case.
- **urgency** (Score, 3 levels): shown only, never used.
- **needs_human** (Noul): shown only, never used.

The model never sets severity. Severity is always the rule's (claims C16 and A3).

## Gold set

`bun src/gold.ts gold/gold.json` builds 39 cases from 11 kinds. Each label comes from how the case was built:

| Label | Kinds | n |
|---|---|---|
| cyberattack | rogue publisher, spoofed MAC, replay, poisoning, forged status | 15 |
| maintenance | test mode, simulation bit, test set on the bus, config change in test mode | 12 |
| device_fault | link loss (×2 seeds), IED restart (×2 seeds) | 12 |

**Limit:** the cases share one generator and are not independent field samples. A PASS means the model reads these evidence patterns. It does not mean the model works on a real substation.

## Stop rule (`STOP_RULE` in `src/eval.ts`)

An answer is **confident** when the winning cause has p ≥ 0.60 and is not `unclear`. Otherwise the board shows "not sure".

A model **PASSES** only if all of these hold:

1. Valid answers ≥ 95% of cases.
2. Not-sure rate ≤ 40% of valid answers.
3. Accuracy of confident answers ≥ 0.80.
4. Every label with ≥ 5 confident predictions has precision ≥ 0.80.

A model that STOPs is still allowed on the board, labelled "not reliable for this pack". The rules work without it.

## Reported per model

`reports/eval-<model>.json`: per-label precision (Wilson 95%) and recall, confident accuracy, not-sure rate, multi-class Brier score, latency p50/p95, typed failures and every prediction.

## Pack 2 (hops), fixed 2026-10-02 before its first run

`src/hops.ts` works in hops:

- **Hop 0 (code):** measures the facts.
- **Hop 1 (model):** a System One Choice between evidence patterns (replay, restart, test equipment, impersonation, other). It runs only for alert classes whose cause depends on the evidence: STNUM_REGRESSION, NEW_PUBLISHER and SQNUM_RESET.
- **Hop 2 (code):** maps each pattern to a cause.

**Held-out gold set:** `gold/gold-v2.json` is built by `bun src/gold.ts gold/gold-v2.json 300`, with seeds 300/400. It has the same 11 kinds and 39 cases, and none of them was seen while designing pack 2.

**Stop rule:** unchanged (`STOP_RULE`). Pack 1 is re-run on gold-v2 so the comparison is like for like.

## Pack 3, fixed 2026-10-02 before its first run

Pack 2 plus one change: classes without a pattern hop get the measured facts together with v1's state, which carries the rule's meaning. Why: in the live story, Nimble on pack 2 read a forged status as a device fault at 0.81.

**Held-out set:** `gold/gold-v3.json` (seeds 500/600). Packs 1, 2 and 3 all run on it. Stop rule unchanged.

### Results on gold-v3 (2026-10-02)

| Model | Pack | Verdict | Not sure | Confident accuracy | Cyberattack recall | p50 |
|---|---|---|---|---|---|---|
| nimble (GPU) | 1 | PASS | 0.08 | 0.92 | 0.60 | 545 ms |
| nimble (GPU) | 2 | PASS | 0.15 | 1.00 | 0.60 | 557 ms |
| nimble (GPU) | 3 | PASS | 0.08 | 1.00 | 0.80 | 475 ms |
| tev1 4B (CPU) | 1 | STOP | 0.64 | 1.00 | 0.00 | 6.8 s |
| tev1 4B (CPU) | 2 | PASS | 0.31 | 1.00 | 0.60 | 6.3 s |
| tev1 4B (CPU) | 3 | PASS | 0.26 | 1.00 | 0.73 | 1.6 s |

Pack 3 is best on both models. When the models are confident, they made no error on this gold set (tev1 on every pack, nimble from pack 2 on). With 9 to 36 confident cases per run, all from one generator, the 95% Wilson lower bound on that 100% is 0.70 to 0.90, so it is not a promise about real traffic; what is left is cyberattacks they mark "not sure", which go to a human.

**Memory:** two resident models (one on the GPU, one on the CPU) can exhaust a 16 GB WSL2 memory limit. Stop the model servers after an eval, or set a short `OLLAMA_KEEP_ALIVE`.
