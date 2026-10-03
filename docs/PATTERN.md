# The pattern: rules, doubt, human

GOOSE Watch is one use of a pattern that fits almost any monitoring job where an AI helps but must not be trusted blindly. This page describes the pattern without the substation, so you can take it anywhere.

```
events ─▶ RULES (code) ──── severity 1–3 ───────────────▶ shown first, always
              │
              └▶ FACTS (code) ─▶ LOCAL AI ─▶ reading + how sure (below 0.60: "not sure")
                                                 │
                                   WHO LOOKS (code) ─▶ "a human checks now" / "no action needed now"
```

## The four parts

1. **Rules decide.** Plain code that catches what must never happen. Rules raise the alert and set its severity. The AI cannot raise, lower or clear one.
2. **Facts are measured in code and handed to the AI.** The AI never gets raw packets or logs. Ask it narrow questions in the domain's own words, over facts you computed. A broad question over raw numbers is where models go confidently wrong.
3. **The AI gives a reading with its doubt.** It picks from a few non-overlapping causes and gives probabilities. Below a threshold fixed in advance (0.60 here) the screen says **not sure**. Don't trust the model's own "choice" field either: recompute the winner from its probabilities.
4. **Code decides who looks.** Severity 2 or 3, an unsure AI, or a suspicious reading means a human checks now. On our test set, the model's own "does a human need to look?" answer gave 0.01 to an attack and 0.99 to a harmless reboot, so we stopped using it.

And one rule around all four: **the AI runs locally.** Monitoring data shows who is home, what runs and where the weak points are. That shouldn't go to a cloud API.

## Before you trust it: measure it

- Write a **gold set** of cases whose right answer you know because you built them. Do it before you run the model even once.
- Fix the **pass bar** in writing first: how often it may say "not sure", and how accurate it must be when it is sure.
- Re-run on **new held-out cases** after every prompt change. Otherwise you are tuning to the test.
- Keep watching it live. Here, the model was right on every confident gold case and still read a live attack as "device fault, 67–68% sure". The rule caught it.

`docs/EVAL.md` shows a worked example.

## Where else it fits

| Domain | Events | A rule | Facts for the AI | Causes |
|---|---|---|---|---|
| Home / SOHO network | ARP, DHCP | unknown device; router address claimed by another MAC | randomized MAC? night time? addresses asked in 10 s | new gadget, own device, scan, impersonation |
| Smart home (Home Assistant) | sensor and door events | door opens while everyone is away | who is home, hour, last motion | family member, delivery, sensor fault, intrusion |
| Small office server | login logs | 10 failed logins in a minute | source country known? usual hour? account exists? | typo, forgotten password, brute force |
| Solar / battery install | inverter readings | output drops > 50% in clear weather | irradiance, other strings, fault codes | shading, soiling, inverter fault, curtailment |
| Substation (this repo) | IEC 61850 GOOSE | state number goes backwards | silence before, timestamp age, sequence number | attack, maintenance, device fault |

`examples/home-watch/` is the first row, ready to run in one file.

## The two tips, in one line each

- **Keep sensitive data on a local AI.**
- **Never let a confident AI have the last word: rules under it, a human over it.**
