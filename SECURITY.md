# Security and safe use

GOOSE Watch is a **passive** monitor. It reads a mirror port or a capture file. It never answers, blocks or injects traffic on a real network.

## The lab tools send frames, so they are fenced

`replay` and the lab scripts emit synthetic GOOSE. GOOSE trips breakers, so the sender refuses to run unless both of these hold:

- the interface is named `gw*` (the lab's veth pair or isolated bridge port);
- the network namespace holds nothing but `lo` and `gw*` links, so any real uplink (`eth0`, `enp1s0`, `vmbr0`, `wlan0`, …) makes it refuse.

`scripts/lab.sh` and `scripts/demo.sh` meet both by running inside `unshare -rnm`: a private namespace with one veth pair and no uplink. `scripts/proxmox-lab.sh` uses a bridge with no physical port and no IP. Never weaken these guards to reach a real bus. See claim A2 in [`docs/CLAIMS.md`](docs/CLAIMS.md).

## Data stays local

The model adapter refuses any endpoint that is not loopback. Do not point it at a hosted model with real substation traffic.

Treat captures from a real site as sensitive. GOOSE string fields (gocbRef, datSet) are attacker-controlled: the rules escape them before display and the model receives them as data, never as instructions (claim C9).

## Reporting a vulnerability

Please open a private security advisory on this repository rather than a public issue.
