# Claims

GOOSE Watch was built against a written list of claims. Each claim says what "done" means and names the probe that would prove it false. The tests, scripts and docs cite these IDs (`C5`, `A2`, …), so you can trace any check back to the promise it guards.

`[x]` means the claim is closed on the evidence named in its probe. `[ ]` means it is still open. Missing numbers (C12, C17, C21–C25, C35) belong to the demo video and the release process, which live outside this repository.

## Principles

- **Rules decide, the model explains.** Deterministic rules are the safety floor. The model only classifies and grades its own uncertainty.
- **Honest uncertainty beats confident guessing.** A "not sure" lane is a feature.
- **Local first.** No byte of capture leaves the machine.

## Anti-claims: what must never happen

- [x] **A1** No real utility capture, IP, hostname, MAC or SCD file appears in the repository or in any hosted API call. All traffic is synthetic. Probe: a scan of the full git history for private identifiers, and an inventory of every IP and MAC ever committed (all synthetic).
- [x] **A2** No GOOSE frame is ever emitted onto a production network by these tools. Probe: the raw-socket sender refuses any interface that is not a veth named `gw*` and any namespace that contains another interface (`test/rawsock.test.ts`; a macvlan named `gw*` refused live), and `scripts/proxmox-lab.sh` refuses a `vmbr9` with a bridge port. Outside the guard's view: where the far end of a veth is plugged in.
- [x] **A3** Model output alone never raises, lowers or clears an alert. Probe: same as C16.
- [x] **A4** The model adapter refuses any endpoint that is not a loopback URL, so this tool sends no capture to a hosted model. Probe: `test/triage.test.ts` (a LAN or remote endpoint is refused). Outside its view: a loopback port that is itself forwarded elsewhere (an SSH tunnel, a proxy).

- [x] **A6** The SCL reader fails closed: a DOCTYPE, an entity declaration, an unknown entity, broken markup or a file over 64 MB is refused, and names from the file are escaped before they are shown. Probe: `test/scl.test.ts` (a billion-laughs file, bidi and control characters in names).
- [x] **A7** The SCD never sets timing or identity: the rules read no MinTime or MaxTime, and time-allowed-to-live and source MACs stay as learned from the capture. Probe: `test/scl.test.ts`.

## Synthetic scenarios

- [x] **C1** The scenario generator writes pcaps whose every frame `tshark` decodes as GOOSE, with gocbRef, stNum, sqNum, TTL, test and simulation fields present. Probe: tshark PDU count equals generator count, for every scenario.

## Decoder and rules

- [x] **C2** `decode` turns a pcap into one event per GOOSE PDU with no loss. Probe: event count equals tshark count on every fixture; fields match tshark.
- [x] **C3** Each anomaly class fires on its scenario, and each scenario raises exactly its expected set: new publisher (unknown block or spoofed MAC), stNum regression, stNum jump, sqNum reset, data change without a new stNum, TTL expiry, test flag, Ed2 simulation bit, configuration revision change. Probe: `bun test`.
- [x] **C4** The clean baseline (≥ 10 simulated minutes, several publishers, normal state changes) and a held-out clean capture raise zero alerts. Probe: `bun test`.
- [x] **C5** Every rule has a negative control: with the rule removed, its test fails. Probe: `scripts/mutate-rules.sh`, 10/10 killed.
- [x] **C9** Hostile gocbRef and datSet strings (prompt-injection text, control and bidi characters) don't change rule outcomes and render escaped. Probe: `bun test` with the `hostile-name` scenario.
- [x] **C26** A lower sequence after a stNum regression never rewinds the stream and never goes unwatched: every sequence rule runs on it from its first frame. It replaces the old sequence only with restart evidence: the old sequence was silent for longer than its learned time-allowed-to-live, and the new message timestamp is between 1 s ahead and 5 s behind the sensor clock. It then needs 3 strictly advancing frames and at least 10 s with no frame from the old sequence. A sequence that rewinds its sqNum loses its claim, an anchor frame cancels the claim but keeps the shadow's rules armed, and only a frame that moves a sequence on counts as the publisher being alive, so a replayed copy of the last frame cannot hold off TTL_EXPIRY. TAL, timestamps and duplicates in a frame cannot shorten any of this. Probe: `test/robustness.test.ts`, including the TAL-1 ms bypass found in review.
- [x] **C27** A frame with a missing or invalid header field (gocbRef, APPID, stNum, sqNum, time-allowed-to-live, confRev, entry count) raises MALFORMED_PDU after the publisher identity checks, and never updates the stream, so it cannot reset detection for the frames after it. A GOOSE PDU without gocbRef or APPID is reported, never dropped or given APPID 0. Probe: `test/robustness.test.ts`.
- [x] **C28** Alerts stay visible and bounded under a flood: at most 256 unknown streams hold their own alerts, an idle one gives its slot back after 60 s, the rest fold into one overflow alert that names the latest offender; a repeat folds into its open alert for at most 60 s and a regression to a different stNum is always a new alert; unknown streams keep no sequence state, the alert list is capped at 10 000, and at most 16 model calls wait while the rest read "AI skipped". Probe: `test/robustness.test.ts`.
- [x] **C29** Each named hardening guard behind C26-C28 and C31 has a negative control: undo it and the suite fails. Probe: `bun scripts/mutate-hardening.ts`, 22/22 killed. It covers the guards listed in the script, not every possible change.
- [x] **C30** Dataset values are compared as tshark's raw allData bytes, so a change of order, of type (integer 7 to unsigned 7) or inside any MMS type such as an octet string raises DATA_WITHOUT_STNUM. Probe: `test/dataset.test.ts`, tshark as oracle.
- [x] **C31** A baseline publisher that sends nothing after the monitor starts raises TTL_EXPIRY (neverSeen) once its learned time-allowed-to-live and a 10 s start-up grace are over. Probe: `test/robustness.test.ts`.
- [x] **C32** A repeat folded into an open alert is printed by `run` at most once per 10 s with its running count, the board updates the card's count, and a restarted board shows the current run again without asking the models. Probe: `test/robustness.test.ts`; board stream checked.
- [x] **C33** `run --stdin` times silence by the frame clock, so a recorded capture piped in raises the same alerts as `--file`; tshark's stderr is read while capturing and an unreadable tshark line is skipped. Probe: `test/live.test.ts`.
- [x] **C36** `run --iface` captures through a kernel filter that keeps every GOOSE frame, untagged or behind one 802.1Q tag, and drops everything else; files and stdin take none. Probe: `scripts/capture-filter-probe.sh` (Linux veth, VLAN rx offload off and on: all GOOSE kept, all Sampled Values noise dropped, a vlan-only mutant loses the untagged half, no filter lets the noise through) and `test/live.test.ts`.
- [x] **C37** Stopping the monitor (SIGINT, SIGTERM, SIGHUP) or a caller that stops reading early also stops its tshark; only SIGKILL cannot be caught. Probe: `test/live.test.ts` (a stand-in tshark that never exits; all four tests fail on the previous decode).
- [x] **C34** Over 1 000 seeded random sequences of traffic, forgeries and garbage: no stream state holds a non-finite number, the anchor never moves back without restart evidence, every bound holds, every alert carries its rule's severity, and the engine is deterministic. Probe: `test/properties.test.ts`.

## SCL import

- [x] **C38** `scl` lists every GOOSE control block in an SCD, CID or ICD: gocbRef (the LD domain, `/LLN0$GO# Claims

GOOSE Watch was built against a written list of claims. Each claim says what "done" means and names the probe that would prove it false. The tests, scripts and docs cite these IDs (`C5`, `A2`, …), so you can trace any check back to the promise it guards.

`[x]` means the claim is closed on the evidence named in its probe. `[ ]` means it is still open. Missing numbers (C12, C17, C21–C25, C35) belong to the demo video and the release process, which live outside this repository.

## Principles

- **Rules decide, the model explains.** Deterministic rules are the safety floor. The model only classifies and grades its own uncertainty.
- **Honest uncertainty beats confident guessing.** A "not sure" lane is a feature.
- **Local first.** No byte of capture leaves the machine.

## Anti-claims: what must never happen

- [x] **A1** No real utility capture, IP, hostname, MAC or SCD file appears in the repository or in any hosted API call. All traffic is synthetic. Probe: a scan of the full git history for private identifiers, and an inventory of every IP and MAC ever committed (all synthetic).
- [x] **A2** No GOOSE frame is ever emitted onto a production network by these tools. Probe: the raw-socket sender refuses any interface that is not a veth named `gw*` and any namespace that contains another interface (`test/rawsock.test.ts`; a macvlan named `gw*` refused live), and `scripts/proxmox-lab.sh` refuses a `vmbr9` with a bridge port. Outside the guard's view: where the far end of a veth is plugged in.
- [x] **A3** Model output alone never raises, lowers or clears an alert. Probe: same as C16.
- [x] **A4** The model adapter refuses any endpoint that is not a loopback URL, so this tool sends no capture to a hosted model. Probe: `test/triage.test.ts` (a LAN or remote endpoint is refused). Outside its view: a loopback port that is itself forwarded elsewhere (an SSH tunnel, a proxy).

- [x] **A6** The SCL reader fails closed: a DOCTYPE, an entity declaration, an unknown entity, broken markup or a file over 64 MB is refused, and names from the file are escaped before they are shown. Probe: `test/scl.test.ts` (a billion-laughs file, bidi and control characters in names).
- [x] **A7** The SCD never sets timing or identity: the rules read no MinTime or MaxTime, and time-allowed-to-live and source MACs stay as learned from the capture. Probe: `test/scl.test.ts`.

## Synthetic scenarios

- [x] **C1** The scenario generator writes pcaps whose every frame `tshark` decodes as GOOSE, with gocbRef, stNum, sqNum, TTL, test and simulation fields present. Probe: tshark PDU count equals generator count, for every scenario.

## Decoder and rules

- [x] **C2** `decode` turns a pcap into one event per GOOSE PDU with no loss. Probe: event count equals tshark count on every fixture; fields match tshark.
- [x] **C3** Each anomaly class fires on its scenario, and each scenario raises exactly its expected set: new publisher (unknown block or spoofed MAC), stNum regression, stNum jump, sqNum reset, data change without a new stNum, TTL expiry, test flag, Ed2 simulation bit, configuration revision change. Probe: `bun test`.
- [x] **C4** The clean baseline (≥ 10 simulated minutes, several publishers, normal state changes) and a held-out clean capture raise zero alerts. Probe: `bun test`.
- [x] **C5** Every rule has a negative control: with the rule removed, its test fails. Probe: `scripts/mutate-rules.sh`, 10/10 killed.
- [x] **C9** Hostile gocbRef and datSet strings (prompt-injection text, control and bidi characters) don't change rule outcomes and render escaped. Probe: `bun test` with the `hostile-name` scenario.
- [x] **C26** A lower sequence after a stNum regression never rewinds the stream and never goes unwatched: every sequence rule runs on it from its first frame. It replaces the old sequence only with restart evidence: the old sequence was silent for longer than its learned time-allowed-to-live, and the new message timestamp is between 1 s ahead and 5 s behind the sensor clock. It then needs 3 strictly advancing frames and at least 10 s with no frame from the old sequence. A sequence that rewinds its sqNum loses its claim, an anchor frame cancels the claim but keeps the shadow's rules armed, and only a frame that moves a sequence on counts as the publisher being alive, so a replayed copy of the last frame cannot hold off TTL_EXPIRY. TAL, timestamps and duplicates in a frame cannot shorten any of this. Probe: `test/robustness.test.ts`, including the TAL-1 ms bypass found in review.
- [x] **C27** A frame with a missing or invalid header field (gocbRef, APPID, stNum, sqNum, time-allowed-to-live, confRev, entry count) raises MALFORMED_PDU after the publisher identity checks, and never updates the stream, so it cannot reset detection for the frames after it. A GOOSE PDU without gocbRef or APPID is reported, never dropped or given APPID 0. Probe: `test/robustness.test.ts`.
- [x] **C28** Alerts stay visible and bounded under a flood: at most 256 unknown streams hold their own alerts, an idle one gives its slot back after 60 s, the rest fold into one overflow alert that names the latest offender; a repeat folds into its open alert for at most 60 s and a regression to a different stNum is always a new alert; unknown streams keep no sequence state, the alert list is capped at 10 000, and at most 16 model calls wait while the rest read "AI skipped". Probe: `test/robustness.test.ts`.
- [x] **C29** Each named hardening guard behind C26-C28 and C31 has a negative control: undo it and the suite fails. Probe: `bun scripts/mutate-hardening.ts`, 22/22 killed. It covers the guards listed in the script, not every possible change.
- [x] **C30** Dataset values are compared as tshark's raw allData bytes, so a change of order, of type (integer 7 to unsigned 7) or inside any MMS type such as an octet string raises DATA_WITHOUT_STNUM. Probe: `test/dataset.test.ts`, tshark as oracle.
- [x] **C31** A baseline publisher that sends nothing after the monitor starts raises TTL_EXPIRY (neverSeen) once its learned time-allowed-to-live and a 10 s start-up grace are over. Probe: `test/robustness.test.ts`.
- [x] **C32** A repeat folded into an open alert is printed by `run` at most once per 10 s with its running count, the board updates the card's count, and a restarted board shows the current run again without asking the models. Probe: `test/robustness.test.ts`; board stream checked.
- [x] **C33** `run --stdin` times silence by the frame clock, so a recorded capture piped in raises the same alerts as `--file`; tshark's stderr is read while capturing and an unreadable tshark line is skipped. Probe: `test/live.test.ts`.
- [x] **C36** `run --iface` captures through a kernel filter that keeps every GOOSE frame, untagged or behind one 802.1Q tag, and drops everything else; files and stdin take none. Probe: `scripts/capture-filter-probe.sh` (Linux veth, VLAN rx offload off and on: all GOOSE kept, all Sampled Values noise dropped, a vlan-only mutant loses the untagged half, no filter lets the noise through) and `test/live.test.ts`.
- [x] **C37** Stopping the monitor (SIGINT, SIGTERM, SIGHUP) or a caller that stops reading early also stops its tshark; only SIGKILL cannot be caught. Probe: `test/live.test.ts` (a stand-in tshark that never exits; all four tests fail on the previous decode).
- [x] **C34** Over 1 000 seeded random sequences of traffic, forgeries and garbage: no stream state holds a non-finite number, the anchor never moves back without restart evidence, every bound holds, every alert carries its rule's severity, and the engine is deterministic. Probe: `test/properties.test.ts`.

, the block name), dataset, confRev, member names in dataset order, and APPID, destination MAC and VLAN from the Communication section (hex, as libiec61850 reads them). GSSE blocks are skipped. Probe: `test/scl.test.ts` (namespace prefixes, Ed2 `ldName`, FCDA without `daName`, a block without address).
- [x] **C39** On the synthetic `fixtures/substation.scd`, `learn --scd` finds no disagreement with the learned baseline, adds member names to every publisher, and every scenario raises the same alerts with and without it. Probe: `test/scl.test.ts`.
- [x] **C40** `learn --scd` names every disagreement between the wire and the SCD: a publisher missing on either side, and a different APPID, dataset, confRev, member count, destination MAC or VLAN; `--strict` exits 1 on any. Probe: `test/scl.test.ts`, one tampered SCD per field.
- [x] **C41** DATA_WITHOUT_STNUM names the member that changed, from the SCD or as `#index` without one, on the CLI and the board. Display only: the rule outcome and everything the model is shown stay byte-identical. Probe: `test/scl.test.ts`; `scripts/mutate-rules.sh` and `bun scripts/mutate-hardening.ts` unchanged.

## Local triage

- [x] **C6** For every alert, the local model returns a validated, typed answer through Ollama's `/v1/systemone`. Invalid or missing answers become a typed failure, never a guess. Probe: a live call on each candidate model.
- [x] **C7** The gold set, class definitions and stop rule are committed **before** the first model run. Probe: `git log` order of `gold/` and `docs/EVAL.md` against `reports/`.
- [x] **C8** Each model gets an eval report with per-class precision and recall (n and Wilson bounds), Brier score, the "not sure" rate and latency p50/p95. Probe: `reports/`.
- [x] **C16** The model can never suppress a rule alarm: the rule engine and the CLI import no model code, and the verdict always carries the rule's severity. Probe: `test/triage.test.ts` (an import check on `src/rules.ts` and `src/cli.ts`, and the adapter forced to maintenance 1.0).
- [x] **C18** Whether a human must look is decided in code, never by the model's needs-a-human answer. Severity 2 or 3, an unsure or unavailable model, or a cyberattack reading means a human checks now. Probe: `test/triage.test.ts` over every class × cause × probability × model answer.

## Live sensor and board

- [x] **C10** Live capture works end to end: a scenario replayed on an isolated link raises the same alerts as the offline decode, with the same PDU ages. Probe: `scripts/live-parity.sh`, 14/14 at 2× (2026-10-03).
- [x] **C11** The board shows each alert with the rule that fired, the model's probabilities and one plain sentence, updating live. Probe: browser screenshot.
- [x] **C13** A lab run can be watched live from a terminal. Probe: `scripts/watch-lab.sh` opens a tmux session with capture, replay and alert panes.
- [x] **C14** A Proxmox deployment is reproducible from the repository, on an isolated bridge with no uplink. Probe: `scripts/proxmox-lab.sh`; a fresh container reached C10 (13/13) on 2026-10-02, on an earlier version with 13 scenarios; not re-run since.
- [x] **C15** The README states what is and is not measured. Probe: read it.

## Reusable pattern

- [x] **C19** A home or small-office version of the pattern runs from one file with no network access, is passive by construction, and its rules are tested with tshark as oracle. Probe: `test/home.test.ts`.
- [x] **C20** `docs/PATTERN.md` states the pattern without the substation, with at least four other domains. Probe: read it.

