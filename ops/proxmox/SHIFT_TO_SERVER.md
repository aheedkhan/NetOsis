# Shift working NetOsis from laptop → Proxmox lab

## Blocker right now

This workstation **cannot reach** Proxmox (`172.30.226.7`) or jump (`172.30.227.1`) — VPN likely down.
Bring lab access up first:

```bash
bash scripts/lab-access/start-vpn-rdp.sh   # or your usual OpenVPN
# then SSH to PVE, e.g.:
ssh root@172.30.226.7
```

## Recommended order (don’t create everything at once)

### Step A — 3 honeypot LXCs first (move the working stack)

On **Proxmox node** (as root), after SDN VNets exist and you have an Ubuntu 22.04 CT template (set `TEMPLATE_CT`):

```bash
# copy repo or just the script onto PVE, then:
TEMPLATE_CT=9000 STORAGE=local-lvm \
  bash scripts/proxmox_create_guests.sh --plan      # review
TEMPLATE_CT=9000 STORAGE=local-lvm \
  bash scripts/proxmox_create_guests.sh --hhp-only  # create 190/290/390
```

| VMID | Hostname | VLAN | IP |
|------|----------|------|-----|
| 190 | finance-db-01 | 10 | 192.168.10.10 |
| 290 | ops-app-01 | 20 | 192.168.20.10 |
| 390 | ent-web-01 | 30 | 192.168.30.10 |

Apply HHP firewall: [`FW_HHP_AND_WAN.md`](FW_HHP_AND_WAN.md).

### Step B — Push code to WEB-HP (390)

On laptop (VPN up), in `.env`:

```bash
LAB_SSH_HOST=192.168.30.10
LAB_SSH_USER=root
# LAB_SSH_JUMP=root@…   # if needed
```

```bash
bash scripts/deploy_to_lab.sh
scp .env root@192.168.30.10:/opt/netosis/.env
ssh root@192.168.30.10 'bash /opt/netosis/scripts/lab-bootstrap-remote.sh'
```

Until SOC exists, either run Ollama **on 390** or keep LLM on laptop (not ideal). Prefer Step C soon.

### Step C — SOC VM (490) for Qwen

Create `netosis-soc` `192.168.40.31` (8GB+ RAM), install Ollama + `qwen2.5:3b`, then on WEB-HP `.env`:

```bash
NETOSIS_LLM_BASE_URL=http://192.168.40.31:11434/v1
NETOSIS_LLM_MODE=qwen
NETOSIS_LLM_MODEL=qwen2.5:3b
systemctl restart netosis-ssh
```

### Step D — Real VMs (web/db/ops/jump)

Create when ready (see script `--all` notes). Not required for first SSH honeypot demo.

### Step E — OPNsense NAT (separate approval)

WAN `:22` → `192.168.30.10:2222`, `:80` → `192.168.30.40:80`.

## What “shifted” means for demos

| Before | After |
|--------|--------|
| Honeypot on laptop `:2222` | Honeypot on LXC 390 (lab IP / WAN NAT) |
| Ollama on laptop | Ollama on SOC `.40.31` |
| Single-host demo | 3 HPs + reals + FW story |
