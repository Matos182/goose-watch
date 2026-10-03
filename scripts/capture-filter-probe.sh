#!/usr/bin/env bash
# C36 probe: the kernel capture filter that `run --iface` hands tshark keeps every GOOSE frame,
# tagged and untagged, and drops everything else, with VLAN rx offload off and on.
# Runs in a user + net namespace (no sudo): one veth pair, a fixture replayed into it, tshark on the
# far end with the exact arguments tsharkArgs() builds. Noise is the same frames re-typed as Sampled
# Values (0x88ba), so a filter that drops nothing fails. A mutant with only the vlan clause must lose
# the untagged GOOSE; no filter at all must show the noise arrived.
# usage: scripts/capture-filter-probe.sh   (needs tshark, tcpreplay, tcprewrite, ethtool, unshare)
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
[ "$(id -u)" = 0 ] || exec unshare -rn "$0" "$@"

d=$(mktemp -d); trap 'ip link del gwfa 2>/dev/null; rm -rf "$d"' EXIT
fx=fixtures/story.pcap   # every fixture frame is 802.1Q-tagged GOOSE
tcprewrite --enet-vlan=del -i "$fx" -o "$d/untagged.pcap" || exit 1
# Re-type each frame's ethertype 0x88b8 -> 0x88ba (after the tag when there is one).
retype='
const [src, dst] = process.argv.slice(1); const b = Buffer.from(await Bun.file(src).arrayBuffer());
for (let o = 24; o + 16 <= b.length; ) { const n = b.readUInt32LE(o + 8), f = o + 16;
  const at = b.readUInt16BE(f + 12) === 0x8100 ? f + 16 : f + 12;
  if (b.readUInt16BE(at) !== 0x88b8) throw new Error("not GOOSE at " + o); b.writeUInt16BE(0x88ba, at); o = f + n; }
await Bun.write(dst, b);'
bun -e "$retype" "$fx" "$d/noise-tagged.pcap" && bun -e "$retype" "$d/untagged.pcap" "$d/noise-untagged.pcap" ||
  { echo "ABORT: noise build failed"; exit 1; }
n=$(tshark -r "$fx" -Y goose 2>/dev/null | wc -l)

mapfile -t args < <(bun -e 'import { tsharkArgs } from "./src/decode"; for (const a of tsharkArgs({ iface: "gwfb" })) console.log(a)')
real=$(bun -e 'import { CAPTURE_FILTER } from "./src/decode"; console.log(CAPTURE_FILTER)')

ip link add gwfa type veth peer name gwfb || exit 1
sysctl -qw net.ipv6.conf.gwfa.disable_ipv6=1 net.ipv6.conf.gwfb.disable_ipv6=1 2>/dev/null
ip link set gwfa up; ip link set gwfb up

# frames <filter|""> [all] -> frames tshark emitted, run with tsharkArgs() except for -f. With "all"
# the -Y goose display filter is dropped too, so every frame the kernel filter passed is counted.
# (tshark's own "packets captured" line counts only what passes -Y, so it cannot show noise.)
frames() {
  local a=() i
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      -f) i=$((i+1)); [ -n "$1" ] && a+=(-f "$1") ;;
      -Y) i=$((i+1)); [ "${2:-}" = all ] || a+=(-Y "${args[$i]}") ;;
      *) a+=("${args[$i]}") ;;
    esac
  done
  tshark "${a[@]}" >"$d/out" 2>"$d/err" & local pid=$!
  sleep 3
  for p in "$fx" "$d/untagged.pcap" "$d/noise-tagged.pcap" "$d/noise-untagged.pcap"; do tcpreplay -q -p 1000 -i gwfa "$p" >/dev/null 2>&1; done
  sleep 2; kill -INT "$pid"; wait "$pid" 2>/dev/null
  # -T ek writes an index line before each frame.
  echo $(( $(grep -c . "$d/out") / 2 ))
}

fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1: $2"; else echo "FAIL $1: got [$2] want [$3]"; fail=1; fi; }
echo "fixture: $n tagged GOOSE frames; sent per run: $n tagged + $n untagged GOOSE, $((2*n)) SV noise"
for off in off on; do
  ethtool -K gwfb rxvlan "$off" >/dev/null 2>&1; ethtool -K gwfa txvlan "$off" >/dev/null 2>&1
  echo "-- rxvlan $off ($(ethtool -k gwfb 2>/dev/null | grep -m1 rx-vlan-offload | tr -d '\t'))"
  check "run --iface args decode every GOOSE frame" "$(frames "$real")" "$((2*n))"
  check "the real filter passes no noise" "$(frames "$real" all)" "$((2*n))"
  check "mutant with only the vlan clause loses the untagged GOOSE" "$(frames 'vlan and ether proto 0x88b8' all)" "$n"
  check "no filter: the noise did arrive" "$(frames '' all)" "$((4*n))"
  # Linux moves the 802.1Q tag into packet metadata before the socket filter runs, so the plain
  # clause alone already matches tagged frames here. Recorded, not asserted: other kernels differ.
  echo "  note: without the vlan clause the kernel passed $(frames 'ether proto 0x88b8' all) frames"
done
[ "$fail" = 0 ] && echo "CAPTURE FILTER PROBE PASS" || { echo "CAPTURE FILTER PROBE FAIL"; exit 1; }
