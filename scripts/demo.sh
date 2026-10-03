#!/usr/bin/env bash
# The live demo on one machine: the isolated lab (namespace, veth gwa → gwb) loops the
# story and appends alerts to reports/live/board.jsonl; the board (host side, loopback)
# tails it, asks the local models and serves http://127.0.0.1:8099.
# usage: scripts/demo.sh [speed]      stop: scripts/demo.sh stop
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
mkdir -p reports/live
if [ "${1:-}" = stop ]; then
  [ -f reports/live/lab.pid ] && kill -- "-$(cat reports/live/lab.pid)" 2>/dev/null || true
  [ -f reports/live/board.pid ] && kill "$(cat reports/live/board.pid)" 2>/dev/null || true
  rm -f reports/live/*.pid; echo stopped; exit 0
fi
speed=${1:-1}
bun src/cli.ts scenarios fixtures >/dev/null
: > reports/live/board.jsonl
setsid nohup unshare -rnm bash -s "$root" "$speed" > reports/live/lab.log 2>&1 <<'INNER' &
set -uo pipefail
root=$1; speed=$2; cd "$root"
mount -t sysfs none /sys
ip link add gwa type veth peer name gwb; ip link set gwa up; ip link set gwb up
while true; do
  echo '{"reset":true}' >> reports/live/board.jsonl
  bun src/cli.ts capture --iface gwb | bun src/cli.ts run --stdin --baseline fixtures/baseline.json --json >> reports/live/board.jsonl &
  sleep 1.5
  bun src/cli.ts replay fixtures/story.pcap --iface gwa --speed "$speed"
  sleep 4
  pkill -f "cli.ts capture --iface gwb"; wait
done
INNER
echo $! > reports/live/lab.pid
nohup bun src/board.ts ${GW_BOARD_ARGS:-} > reports/live/board.log 2>&1 &
echo $! > reports/live/board.pid
sleep 1; cat reports/live/board.log
