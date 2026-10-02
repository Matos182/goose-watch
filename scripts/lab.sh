#!/usr/bin/env bash
# Isolated live lab: a private user+network namespace with one veth pair (gwa → gwb)
# and no uplink. Replays a scenario on gwa, captures on gwb, runs the rules live.
# usage: scripts/lab.sh <scenario> [speed] [outdir]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
scenario=${1:?scenario name}; speed=${2:-1}; out=${3:-$root/reports/live}
mkdir -p "$out"
[ -f "$root/fixtures/$scenario.pcap" ] || (cd "$root" && bun src/cli.ts scenarios fixtures >/dev/null)
exec unshare -rnm bash -s "$root" "$scenario" "$speed" "$out" <<'INNER'
set -euo pipefail
root=$1; scenario=$2; speed=$3; out=$4
mount -t sysfs none /sys
ip link add gwa type veth peer name gwb
ip link set gwa up; ip link set gwb up
cd "$root"
bun src/cli.ts capture --iface gwb | bun src/cli.ts run --stdin --baseline fixtures/baseline.json --json > "$out/$scenario.alerts.jsonl" &
sleep 1.5
bun src/cli.ts replay "fixtures/$scenario.pcap" --iface gwa --speed "$speed"
sleep 0.5 # stop right after the last frame: end-of-replay silence is not part of the scenario
kill %1 2>/dev/null || true
wait 2>/dev/null || true
INNER
