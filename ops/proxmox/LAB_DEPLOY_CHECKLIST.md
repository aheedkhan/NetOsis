# Lab deploy checklist (apply only with explicit approval)

## Forms

* **3× LXC HPs** at `.10`: FIN `192.168.10.10`, OPS `192.168.20.10`, WEB `192.168.30.10`
* **VMs**: FINANCE-DB `.10.50`, OPS-APP `.20.50`, ENT-WEB `.30.40`, ENT-JUMP `.30.31`, SOC `.40.31`

## Steps (manual)

1. Confirm SDN VNets FIN/OPS/ENT/SOC on `vmbr1`.
2. Create LXCs + VMs with static IPs above; GW `.254`.
3. Proxmox FW on each HHP per `ops/proxmox/FW_HHP_AND_WAN.md`.
4. OPNsense WAN NAT: `:80`→`.30.40:80`, `:22`→`.30.10:2222`.
5. SOC: Ollama `qwen2.5:3b`, NetOsis, optional sandbox API `:8000`, later k3s.
6. Deploy `netosis-ssh.service` on WEB-HP; `.env` points LLM to `http://192.168.40.31:11434/v1`.
7. Phase-2 only: set `NETOSIS_SANDBOX_URL=http://192.168.40.31:8000`.

## Verify

* From Kali: `nmap -sV` WAN → 22+80 open, else filtered.
* SSH `admin` / `admin123` → fake shell; `curl https://example.com -o x` → sandbox job + file in virtual FS.
* HHP cannot TCP to `.50` (Proxmox FW).
