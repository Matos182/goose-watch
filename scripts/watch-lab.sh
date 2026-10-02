#!/usr/bin/env bash
# Start (or restart) the observable lab on this machine: a tmux server living inside a
# private user+network namespace with one veth pair (gwa → gwb) and no uplink.
#   attach to watch:  tmux -S /tmp/goosewatch.sock attach -r
#   stop:             tmux -S /tmp/goosewatch.sock kill-server
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
sock=/tmp/goosewatch.sock
speed=${1:-1}
tmux -S "$sock" kill-server 2>/dev/null || true
(cd "$root" && bun src/cli.ts scenarios fixtures >/dev/null)
exec unshare -rnm bash -s "$root" "$sock" "$speed" <<'INNER'
set -euo pipefail
root=$1; sock=$2; speed=$3
mount -t sysfs none /sys
ip link add gwa type veth peer name gwb; ip link set gwa up; ip link set gwb up
pane="$root/scripts/lab-pane.sh"
tmux -S "$sock" new-session -d -s goosewatch -x 220 -y 50 "$pane alerts; exec bash"
tmux -S "$sock" split-window -v -l 40% -t goosewatch "$pane replay $speed; exec bash"
tmux -S "$sock" split-window -h -t goosewatch "$pane wire; exec bash"
tmux -S "$sock" select-pane -t goosewatch -U
chmod 600 "$sock"
INNER
