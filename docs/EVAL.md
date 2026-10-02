# Model evaluation: classes, gold set and stop rule

Fixed on 2026-10-02, **before the first model run** (claim C7). Changing anything here after a run needs a new held-out gold set (seeds ≥ 300), never a re-run on this one.

## What the model is asked

Pack `triage-pack-1` (`src/triage.ts`) asks three questions about one alert:

- **cause** (Choice): `cyberattack` · `maintenance` · `device_fault` · `unclear`. The descriptions in the code are written so that no two of them cover the same case.
- **urgency** (Score, 3 levels): shown only, never used.
- **needs_human** (Noul): shown only, never used.

The model never sets severity. Severity is always the rule's (claims C16/A3).

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
