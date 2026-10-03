#!/usr/bin/env bash
# Reproduce the Proxmox lab (run on the Proxmox host as root, with goose-watch.tgz and a bun binary in /root).
#   vmbr9  isolated bridge, no physical port, no IP
#   120    goose-sensor: eth0 on vmbr0 (management/apt), gw0 on vmbr9 (listen only)
#   121    goose-pub:    gw0 on vmbr9 only (no uplink at all), replays synthetic GOOSE
# Verified 2026-10-02: live parity 13/13 across vmbr9 (sensor uses tshark -i gw0).
# Undo: pct stop 120 121; pct destroy 120; pct destroy 121; pvesh delete /nodes/pve/network/vmbr9; pvesh set /nodes/pve/network
set -euo pipefail
node=$(hostname)
T=local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst
cp /etc/network/interfaces "/root/interfaces.pre-goosewatch-$(date +%F)"
pvesh get /nodes/$node/network/vmbr9 >/dev/null 2>&1 || {
  pvesh create /nodes/$node/network --iface vmbr9 --type bridge --autostart 1 --comments "GOOSE Watch isolated lab bridge - no uplink"
  pvesh set /nodes/$node/network
}
# An existing vmbr9 is reused only if it has no port: lab GOOSE must have no way onto a real network.
# Fail closed: a failed query, or a port named in any JSON spacing, stops the script.
vmbr9=$(pvesh get /nodes/$node/network/vmbr9 --output-format json) || { echo "refusing: cannot read vmbr9" >&2; exit 1; }
ports=$(printf '%s' "$vmbr9" | sed -n 's/.*"bridge_ports"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
case "$ports" in ""|none) ;; *) echo "refusing: vmbr9 has bridge ports ($ports); the lab bridge must have no uplink" >&2; exit 1 ;; esac
pveam list local | grep -q debian-13-standard_13.6-1 || pveam download local debian-13-standard_13.6-1_amd64.tar.zst
pct status 120 >/dev/null 2>&1 || pct create 120 $T --hostname goose-sensor --unprivileged 1 --features nesting=1 --cores 2 --memory 2048 --swap 512 \
  --rootfs local-lvm:8 --net0 name=eth0,bridge=vmbr0,ip=dhcp,firewall=1 --net1 name=gw0,bridge=vmbr9 --onboot 0
pct status 121 >/dev/null 2>&1 || pct create 121 $T --hostname goose-pub --unprivileged 1 --cores 1 --memory 512 --swap 0 \
  --rootfs local-lvm:4 --net0 name=gw0,bridge=vmbr9 --onboot 0
pct start 120 2>/dev/null || true; pct start 121 2>/dev/null || true; sleep 5
for c in 120 121; do
  pct exec $c -- bash -c 'grep -q gw0 /etc/network/interfaces || printf "auto gw0\niface gw0 inet manual\n" >> /etc/network/interfaces; ip link set gw0 up'
  pct exec $c -- mkdir -p /opt/goose-watch
  pct push $c /root/goose-watch.tgz /opt/goose-watch.tgz
  pct exec $c -- tar xzf /opt/goose-watch.tgz -C /opt/goose-watch
  pct push $c /root/bun.bin /usr/local/bin/bun --perms 755
done
pct exec 120 -- bash -c 'export DEBIAN_FRONTEND=noninteractive; echo wireshark-common wireshark-common/install-setuid boolean false | debconf-set-selections; apt-get update -qq; apt-get install -y -qq tshark'
echo "sensor: pct exec 120 -- bash -c 'cd /opt/goose-watch && /usr/local/bin/bun src/cli.ts run --iface gw0 --baseline fixtures/baseline.json'"
echo "publish: pct exec 121 -- bash -c 'cd /opt/goose-watch && /usr/local/bin/bun src/cli.ts replay fixtures/story.pcap --iface gw0'"
