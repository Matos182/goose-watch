# Security and safe use

GOOSE Watch is a **passive** monitor. It reads a mirror port or a capture file. It never answers, blocks or injects traffic on a real network.

## The lab tools send frames, so they are fenced

`replay` and the lab scripts emit synthetic GOOSE. GOOSE trips breakers, so the sender refuses to run unless both of these hold:

- the interface is a veth named `gw*` (the lab's veth pair or isolated bridge port); a macvlan, ipvlan, VLAN or renamed NIC is refused whatever its name;
- the network namespace holds nothing but `lo` and `gw*` links, so any real uplink (`eth0`, `enp1s0`, `vmbr0`, `wlan0`, …) makes it refuse.

`scripts/lab.sh` and `scripts/demo.sh` meet both by running inside `unshare -rnm`: a private namespace with one veth pair and no uplink. `scripts/proxmox-lab.sh` uses a bridge with no physical port and no IP, and refuses to reuse a `vmbr9` that has one. The guard cannot see where the far end of a veth is plugged in, so never bridge a lab veth to a real port. Never weaken these guards to reach a real bus. See claim A2 in [`docs/CLAIMS.md`](docs/CLAIMS.md).

## Data stays local

The model adapter refuses any endpoint that is not loopback. Do not point it at a hosted model with real substation traffic.

Treat captures from a real site as sensitive. GOOSE string fields (gocbRef, datSet) are attacker-controlled: the board shows them through `safeText` (controls, bidi, zero-width and Unicode tag characters removed, length capped) and only as text. The model receives the same cleaned, capped string; a model can still be steered by text, which is why it never raises, lowers or clears an alert (claims C9, C16). `run --json` prints the raw fields as JSON, so treat them as untrusted in anything that consumes it.

## Reporting a vulnerability

Please open a private security advisory on this repository rather than a public issue.
