# Eval reports

One JSON report per model, prompt pack and gold set, written by `src/eval.ts`. Each holds per-class precision and recall with Wilson bounds, the Brier score, the "not sure" rate, latency p50/p95 and every raw answer.

File names read `eval-<model>[-pack<N>]-<gold>.json`:

- no pack suffix means pack 1, the single broad cause question;
- no gold suffix means the first gold set (`gold/gold.json`).

| Gold set | Fixed before | Reports |
|---|---|---|
| `gold.json` | the first model run | `eval-*_latest.json`, `eval-tev1_0.8b.json` |
| `gold-v2.json` | the first pack 2 run | `*-goldv2.json` |
| `gold-v3.json` | the first pack 3 run | `*-goldv3.json` (the table in the README) |

Every gold set was committed before any run against it, so `git log` shows that no result shaped the labels. Superseded reports are kept on purpose: they record what each pack got wrong. The method and stop rule live in [`docs/EVAL.md`](../docs/EVAL.md).
