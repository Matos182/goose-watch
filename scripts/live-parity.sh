#!/usr/bin/env bash
# C10 probe: every scenario replayed live through the lab link must raise the same
# (class, stream) set as the offline decode of the same pcap.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
# Speed 4, not 10: at 10x the story's lost link is shorter than timeAllowedToLive in real time, so
# TTL_EXPIRY cannot fire live (a speed artifact, not a sensor defect).
speed=${1:-4}; ok=0; n=0
for f in fixtures/*.pcap; do
  s=$(basename "$f" .pcap); n=$((n+1))
  off=$(bun src/cli.ts run --file "$f" --baseline fixtures/baseline.json --json | bun -e 'const t=await Bun.stdin.text();console.log([...new Set(t.trim().split("\n").filter(Boolean).map(l=>{const a=JSON.parse(l);return a.cls+"@"+a.key.split("|")[0]}))].sort().join(" "))')
  scripts/lab.sh "$s" "$speed" >/dev/null 2>&1
  live=$(bun -e 'const t=await Bun.file(process.argv[1]).text();console.log([...new Set(t.trim().split("\n").filter(Boolean).map(l=>{const a=JSON.parse(l);return a.cls+"@"+a.key.split("|")[0]}))].sort().join(" "))' "reports/live/$s.alerts.jsonl")
  if [ "$off" = "$live" ]; then ok=$((ok+1)); echo "PASS $s: ${off:-silence}"; else echo "FAIL $s: offline=[$off] live=[$live]"; fi
done
echo "live parity: $ok/$n"
[ "$ok" -eq "$n" ]
