#!/usr/bin/env bash
# C10 probe: every scenario replayed live through the lab link must raise the same
# (class, stream) set as the offline decode of the same pcap.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
# Speed 2, not 4: timeAllowedToLive (2 s) is real time and does not scale with replay speed. At 4x the
# simulation-bit scenario's 5 s of ignored frames last 1.25 s, shorter than the TAL, so TTL_EXPIRY cannot
# fire live (a speed artifact, not a sensor defect). At 2x they last 2.5 s.
speed=${1:-2}; ok=0; n=0
for f in fixtures/*.pcap; do
  s=$(basename "$f" .pcap); n=$((n+1))
  off=$(bun src/cli.ts run --file "$f" --baseline fixtures/baseline.json --json | bun -e 'const t=await Bun.stdin.text();console.log([...new Set(t.trim().split("\n").filter(Boolean).map(l=>JSON.parse(l)).filter(a=>a.cls).map(a=>a.cls+"@"+a.key.split("|")[0]))].sort().join(" "))')
  scripts/lab.sh "$s" "$speed" >/dev/null 2>&1
  live=$(bun -e 'const t=await Bun.file(process.argv[1]).text();console.log([...new Set(t.trim().split("\n").filter(Boolean).map(l=>JSON.parse(l)).filter(a=>a.cls).map(a=>a.cls+"@"+a.key.split("|")[0]))].sort().join(" "))' "reports/live/$s.alerts.jsonl")
  if [ "$off" = "$live" ]; then ok=$((ok+1)); echo "PASS $s: ${off:-silence}"; else echo "FAIL $s: offline=[$off] live=[$live]"; fi
done
echo "live parity: $ok/$n"
[ "$ok" -eq "$n" ]
