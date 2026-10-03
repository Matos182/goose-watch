# Claims

GOOSE Watch was built against a written list of claims. Each claim says what "done" means and names the probe that would prove it false. The tests, scripts and docs cite these IDs (`C5`, `A2`, …), so you can trace any check back to the promise it guards.

`[x]` means the claim is closed on the evidence named in its probe. `[ ]` means it is still open.

## Principles

- **Rules decide, the model explains.** Deterministic rules are the safety floor. The model only classifies and grades its own uncertainty.
- **Honest uncertainty beats confident guessing.** A "not sure" lane is a feature.
- **Local first.** No byte of capture leaves the machine.

## Anti-claims: what must never happen

- [x] **A1** No real utility capture, IP, hostname, MAC or SCD file appears in the repository or in any hosted API call. All traffic is synthetic. Probe: a scan of the full git history for private identifiers, and an inventory of every IP and MAC ever committed (all synthetic).
- [x] **A2** No GOOSE frame is ever emitted onto a production network. Probe: the raw-socket sender refuses any interface not named `gw*` and any namespace that contains a real interface (`test/rawsock.test.ts`).
- [x] **A3** Model output alone never raises, lowers or clears an alert. Probe: same as C16.
- [x] **A4** No capture reaches a hosted model: the model adapter accepts only a loopback endpoint. Probe: `test/triage.test.ts` (a LAN or remote endpoint is refused).

## Synthetic scenarios

- [x] **C1** The scenario generator writes pcaps whose every frame `tshark` decodes as GOOSE, with gocbRef, stNum, sqNum, TTL, test and simulation fields present. Probe: tshark PDU count equals generator count, for every scenario.

## Decoder and rules

- [x] **C2** `decode` turns a pcap into one event per GOOSE PDU with no loss. Probe: event count equals tshark count on every fixture; fields match tshark.
- [x] **C3** Each anomaly class fires on its scenario, and each scenario raises exactly its expected set: new publisher (unknown block or spoofed MAC), stNum regression, stNum jump, sqNum reset, data change without a new stNum, TTL expiry, test flag, Ed2 simulation bit, configuration revision change. Probe: `bun test`.
- [x] **C4** The clean baseline (≥ 10 simulated minutes, several publishers, normal state changes) and a held-out clean capture raise zero alerts. Probe: `bun test`.
- [x] **C5** Every rule has a negative control: with the rule removed, its test fails. Probe: `scripts/mutate-rules.sh`, 9/9 killed.
- [x] **C9** Hostile gocbRef and datSet strings (prompt-injection text, control and bidi characters) don't change rule outcomes and render escaped. Probe: `bun test` with the `hostile-name` scenario.

## Local triage

- [x] **C6** For every alert, the local model returns a validated, typed answer through Ollama's `/v1/systemone`. Invalid or missing answers become a typed failure, never a guess. Probe: a live call on each candidate model.
- [x] **C7** The gold set, class definitions and stop rule are committed **before** the first model run. Probe: `git log` order of `gold/` and `docs/EVAL.md` against `reports/`.
- [x] **C8** Each model gets an eval report with per-class precision and recall (n and Wilson bounds), Brier score, the "not sure" rate and latency p50/p95. Probe: `reports/`.
- [x] **C16** The model can never suppress a rule alarm. Probe: `bun test` with the adapter forced to "normal 1.0"; the alert keeps its full severity.
- [x] **C18** Whether a human must look is decided in code, never by the model's needs-a-human answer. Severity 2 or 3, an unsure or unavailable model, or a cyberattack reading means a human checks now. Probe: `test/triage.test.ts` over every class × cause × probability × model answer.

## Live sensor and board

- [x] **C10** Live capture works end to end: a scenario replayed on an isolated link raises the same alerts as the offline decode, with the same PDU ages. Probe: `scripts/live-parity.sh`, 14/14 at 4×.
- [x] **C11** The board shows each alert with the rule that fired, the model's probabilities and one plain sentence, updating live. Probe: browser screenshot.
- [ ] **C13** A lab run can be watched live from a terminal. Probe: `scripts/watch-lab.sh` opens a tmux session with capture, replay and alert panes.
- [x] **C14** A Proxmox deployment is reproducible from the repository, on an isolated bridge with no uplink. Probe: `scripts/proxmox-lab.sh`; a fresh container reaches C10 (13/13).
- [x] **C15** The README states what is and is not measured. Probe: read it.

## Reusable pattern

- [x] **C19** A home or small-office version of the pattern runs from one file with no network access, is passive by construction, and its rules are tested with tshark as oracle. Probe: `test/home.test.ts`.
- [x] **C20** `docs/PATTERN.md` states the pattern without the substation, with at least four other domains. Probe: read it.

