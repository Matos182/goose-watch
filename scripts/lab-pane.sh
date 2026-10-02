#!/usr/bin/env bash
# One pane of the observable lab. Runs inside the lab namespace (started by watch-lab.sh).
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
case "$1" in
  alerts)
    while true; do
      clear
      echo "── ALERTS · the rules decide · severity 1 note · 2 investigate · 3 act now ──"
      bun src/cli.ts capture --iface gwb | bun src/cli.ts run --stdin --baseline fixtures/baseline.json
      sleep 0.5
    done ;;
  wire)
    echo "── WIRE · GOOSE on the lab link: src · gocbRef · stNum · sqNum · test ──"
    bun src/cli.ts capture --iface gwb | tshark -r - -l -Y goose -T fields -E separator='  ' \
      -e eth.src -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.simulation 2>/dev/null ;;
  replay)
    speed=${2:-1}
    while true; do
      pkill -f "cli.ts run --stdin" 2>/dev/null   # fresh rule engine for each loop of the story
      sleep 1
      printf '\n▶ %s  story (x%s): 5 minutes of a substation bus\n' "$(date +%T)" "$speed"
      printf '   %s\n' "0:40 relay put in test mode (maintenance)" "1:10 an unknown device starts publishing" \
        "1:50 an old breaker message is replayed" "2:20 the protection relay goes silent for 10 s" \
        "3:00 the breaker status is forged" "3:40 GOOSE poisoning on the busbar block"
      bun src/cli.ts replay fixtures/story.pcap --iface gwa --speed "$speed"
    done ;;
esac
