# Server runbook — clone & run (Days 1–3)

Order matters: **install everything while guests still have Internet, then lock down.**
All guest shells: Proxmox host → `pct enter <CTID>` (CTs) or the VM console — no SSH
needed on the honeypots, so nothing extra is exposed.

Placeholders: `<FW_WAN_IP>` = OPNsense WAN address on tag 227, `<KALI_IP>` = Kali.

---

## 0. Proxmox host (once)

```bash
# CT105 is missing firewall=1 on its NIC (rules would silently not apply)
pct set 105 -net0 name=eth0,bridge=vmbr1,firewall=1,gw=192.168.20.254,hwaddr=BC:24:11:B9:65:16,ip=192.168.20.10/24,tag=20,type=veth
```

Enable the firewall *engine* without filtering the Proxmox host itself (no lock-out
risk). `/etc/pve/firewall/cluster.fw`:

```ini
[OPTIONS]
enable: 1
policy_in: ACCEPT
policy_out: ACCEPT
```

## 1. SOC controller — VM103 (192.168.40.31, Ubuntu 26.04, user `controller` → use `sudo -i` first)

```bash
git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis
bash /opt/netosis/scripts/soc-setup.sh          # Ollama on :11434 + 3 Qwen sizes
python3 /opt/netosis/scripts/llm_bench.py       # choose model (p95 < ~4 s)
```

Write the chosen model into every `deception/hosts/*.ssh.env`
(`NETOSIS_LLM_MODEL=...`), commit + push, or edit `/opt/netosis/.env` on each CT.

## 2. Enterprise honeypot — CT102 (192.168.30.10)

```bash
pct enter 102
git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis
bash /opt/netosis/scripts/lab-bootstrap-remote.sh ent-web-01
ssh admin@127.0.0.1 -p 2222        # password admin123 — try: ls, cat notes.txt, df -h
journalctl -u netosis-ssh -f       # [det]/[llm] lines per command
```

### 2b. Pre-generate answers with the big model (runs ~1 h, in background)

Live answers use `qwen2.5:0.5b` (~6 s on this CPU). Common commands are
pre-generated once by `qwen2.5:3b` so attackers get them instantly:

```bash
cd /opt/netosis
nohup .venv/bin/python scripts/llm_prewarm.py --model qwen2.5:3b > data/prewarm.log 2>&1 &
tail -f data/prewarm.log          # Ctrl-C only stops tail; job keeps running
```

Same later for **CT104** (`finance-db-01`) and **CT105** (`ops-app-01`).
Update after a push: `cd /opt/netosis && git pull && bash scripts/lab-bootstrap-remote.sh ent-web-01`.

If the service fails with `status=226/NAMESPACE` (unprivileged LXC), comment out
`PrivateTmp`/`ProtectSystem`/`ProtectHome` in `/etc/systemd/system/netosis-ssh.service`,
then `systemctl daemon-reload && systemctl restart netosis-ssh`.

## 2c. Real servers (the assets honeypots must never reach)

Proxmox host shell — reuse the Ubuntu CT template the honeypots were made from:

```bash
pveam list local                     # copy the vztmpl name, e.g. local:vztmpl/ubuntu-24.04-standard_...
T=local:vztmpl/<template-name>
pct create 310 $T --hostname ent-web-real-01 --cores 1 --memory 1024 --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr1,tag=30,ip=192.168.30.40/24,gw=192.168.30.254,firewall=1 \
  --unprivileged 1 --features nesting=1 --onboot 1 --start 1
pct create 110 $T --hostname finance-db-real-01 --cores 1 --memory 1024 --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr1,tag=10,ip=192.168.10.50/24,gw=192.168.10.254,firewall=1 \
  --unprivileged 1 --features nesting=1 --onboot 1 --start 1
pct create 210 $T --hostname ops-app-real-01 --cores 1 --memory 1024 --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr1,tag=20,ip=192.168.20.50/24,gw=192.168.20.254,firewall=1 \
  --unprivileged 1 --features nesting=1 --onboot 1 --start 1
```

Inside each (`pct enter 310|110|210`):

```bash
apt-get update -qq && apt-get install -y -qq curl
curl -fsSL https://raw.githubusercontent.com/aheedkhan/NetOsis/main/scripts/real-server-setup.sh | bash -s web   # 310
#                                                                                         ... bash -s db    # 110
#                                                                                         ... bash -s app   # 210
```

## 3. Lock down (after step 1–2 work)

`/etc/pve/firewall/102.fw` (copy to `104.fw`, `105.fw`):

```ini
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: DROP

[RULES]
IN ACCEPT -p tcp -dport 2222 -log nolog
OUT ACCEPT -d 192.168.40.31 -p tcp -dport 11434 -log nolog
OUT ACCEPT -d 192.168.40.31 -p tcp -dport 8000 -log nolog
```

Need apt/git on a honeypot again? set `enable: 0`, do the work, set `enable: 1`.

`/etc/pve/firewall/103.fw` (SOC: only honeypots may reach Ollama/API):

```ini
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[RULES]
IN ACCEPT -source 192.168.10.10,192.168.20.10,192.168.30.10 -p tcp -dport 11434 -log nolog
IN ACCEPT -source 192.168.10.10,192.168.20.10,192.168.30.10 -p tcp -dport 8000 -log nolog
```

`/etc/pve/firewall/106.fw` (Kali sees only the FW WAN — not the Jbox):

```ini
[OPTIONS]
enable: 1
policy_in: ACCEPT
policy_out: DROP

[RULES]
OUT ACCEPT -d <FW_WAN_IP> -log nolog
```

Check: `pve-firewall status` → `enabled/running`.

## 4. OPNsense (GUI from the Jbox)

1. **System → Settings → Administration**: Web GUI *Listen interfaces* = LAN;
   Secure Shell *Listen interfaces* = LAN. (Nothing of OPNsense itself on WAN.)
2. **Interfaces → WAN**: untick **Block private networks** and **Block bogon
   networks** — the lab "public" segment is a private range, so OPNsense would
   otherwise drop every Kali packet.
3. **Firewall → Rules → ENTERPRISE_VLAN30 / FINANCE_VLAN10 / OPERATIONS_VLAN20**
   (top to bottom):
   - Pass TCP `<honeypot .10>` → `192.168.40.31` ports `11434`, `8000`
   - Block any → `192.168.0.0/16` (other VLANs, LAN, Jbox leg)
   - Block any → `172.16.0.0/12`, `10.0.0.0/8`
   - Internet: keep a pass-any rule only while installing; then delete it.
4. **Firewall → NAT → Port Forward**: Interface WAN, TCP, destination *WAN address*
   port `22` → redirect `192.168.30.10` port `2222`, filter rule = *Add associated
   filter rule*. Apply.

## 5. Verify from Kali

```bash
nmap -Pn -sV <FW_WAN_IP>          # only 22/tcp open, banner OpenSSH 8.9p1 Ubuntu
ssh admin@<FW_WAN_IP>             # lands in ent-web-01 fake shell
ping 172.30.227.1                 # must FAIL (Jbox protected)
```

On CT102: `tail -f /opt/netosis/data/telemetry.jsonl` shows `source_ip` = Kali's IP,
`auth_failure`/`auth_success` + `command` events.
