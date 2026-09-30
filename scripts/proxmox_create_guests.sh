#!/usr/bin/env bash
# Create NetOsis FYP guests on Proxmox (run ON the PVE node as root).
# Does NOT touch OPNsense NAT. Review before each create.
#
# Usage:
#   bash scripts/proxmox_create_guests.sh --plan          # print commands only
#   bash scripts/proxmox_create_guests.sh --hhp-only       # create 3 LXC honeypots
#   bash scripts/proxmox_create_guests.sh --all            # HHP LXCs + stub note for VMs
#
# Prerequisites on PVE:
#   - SDN VNets FIN/OPS/ENT/SOC (or VLAN-aware vmbr1 with tags)
#   - Local template CT available (set TEMPLATE_CT below)
#   - Storage name (set STORAGE)
set -euo pipefail

PLAN_ONLY=0
HHP_ONLY=0
DO_ALL=0
TEMPLATE_CT="${TEMPLATE_CT:-9000}"          # ubuntu-22.04 CT template VMID
STORAGE="${STORAGE:-local-lvm}"
BRIDGE="${BRIDGE:-vmbr1}"
PASSWORD="${CT_ROOT_PASSWORD:-ChangeMeNow!}"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# //'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_ONLY=1 ;;
    --hhp-only) HHP_ONLY=1 ;;
    --all) DO_ALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
  shift
done

if [[ "$HHP_ONLY" -eq 0 && "$DO_ALL" -eq 0 && "$PLAN_ONLY" -eq 0 ]]; then
  echo "[!] Pass --plan, --hhp-only, or --all"
  usage
  exit 1
fi

run() {
  echo "+ $*"
  if [[ "$PLAN_ONLY" -eq 1 ]]; then
    return 0
  fi
  eval "$@"
}

create_hhp_lxc() {
  local vmid="$1" hostname="$2" tag="$3" ip="$4" gw="$5"
  # Skip if exists
  if [[ "$PLAN_ONLY" -eq 0 ]] && pct status "$vmid" &>/dev/null; then
    echo "[*] CT $vmid already exists — skip"
    return 0
  fi
  run pct clone "$TEMPLATE_CT" "$vmid" --hostname "$hostname" --full 1 --storage "$STORAGE"
  run pct set "$vmid" \
    --net0 "name=eth0,bridge=${BRIDGE},tag=${tag},firewall=1,ip=${ip}/24,gw=${gw}" \
    --memory 512 --cores 1 --swap 512 \
    --onboot 1 \
    --unprivileged 1 \
    --features nesting=1 \
    --password "'$PASSWORD'"
  run pct start "$vmid" || true
  echo "[+] HHP LXC $vmid $hostname $ip vlan$tag"
}

echo "=== NetOsis guest create (TEMPLATE_CT=$TEMPLATE_CT STORAGE=$STORAGE BRIDGE=$BRIDGE) ==="

# --- 3 honeypot LXCs (priority: move working stack here) ---
if [[ "$HHP_ONLY" -eq 1 || "$DO_ALL" -eq 1 || "$PLAN_ONLY" -eq 1 ]]; then
  create_hhp_lxc 190 finance-db-01 10 192.168.10.10 192.168.10.254
  create_hhp_lxc 290 ops-app-01     20 192.168.20.10 192.168.20.254
  create_hhp_lxc 390 ent-web-01     30 192.168.30.10 192.168.30.254
fi

if [[ "$DO_ALL" -eq 1 || "$PLAN_ONLY" -eq 1 ]]; then
  cat <<'EOF'

=== Real VMs (create via UI or qm — heavier) ===
Suggested VMIDs / IPs (Ubuntu cloud images recommended):
  191  FINANCE-DB-REAL-01   192.168.10.50/24  gw .254  vlan 10   mem 2048
  291  OPS-APP-REAL-01      192.168.20.50/24  gw .254  vlan 20   mem 2048
  391  ENT-JUMP-01          192.168.30.31/24  gw .254  vlan 30   mem 1024
  392  ENT-WEB-REAL-01      192.168.30.40/24  gw .254  vlan 30   mem 1024  (nginx)
  490  netosis-soc          192.168.40.31/24  gw .254  vlan 40   mem 8192  (Ollama+NetOsis)

Example:
  qm create 392 --name ent-web-real-01 --memory 1024 --cores 2 --net0 virtio,bridge=vmbr1,tag=30,firewall=1
  # then attach cloud-init disk, set IP 192.168.30.40/24, install nginx

After WEB-HP (390) is up:
  # from laptop (VPN + LAB_SSH_*):
  #   set LAB_SSH_HOST=192.168.30.10 in .env
  #   bash scripts/deploy_to_lab.sh
  #   scp .env root@192.168.30.10:/opt/netosis/.env
  #   ssh root@192.168.30.10 'bash /opt/netosis/scripts/lab-bootstrap-remote.sh'
  # Point NETOSIS_LLM_BASE_URL at SOC once 490 has Ollama:
  #   NETOSIS_LLM_BASE_URL=http://192.168.40.31:11434/v1

Proxmox FW on each HHP: see ops/proxmox/FW_HHP_AND_WAN.md
OPNsense NAT: see ops/opnsense/PROPOSED_WAN_NAT.md (approve separately)
EOF
fi

echo "=== done ==="
