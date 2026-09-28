# SSH honeypot front-door (lab)

## Purpose

Expose the NetOsis fake shell on a real TCP port so you can SSH in from another
machine and exercise deterministic commands + RAG/Qwen fallback.

## Safety

- Bind to a **lab VLAN / test IP**, not the Proxmox management plane if you can avoid it.
- Default port **2222** (not 22) so you do not collide with real SSH.
- Login is **admin / admin123** by default (weak decoy). Wrong passwords fail so it does not look like an open honeypot.
- Host key is stored under `data/ssh_host_rsa_key` (gitignored).
- Do not put this on the public Internet without a written threat model.

## Prerequisites

```bash
source .venv/bin/activate
pip install -r requirements.txt          # includes paramiko
ollama pull qwen2.5:3b                   # CPU-friendly; see docs/llm-local.md
```

Confirm the light model is present (avoid accidental 27B/30B):

```bash
ollama list | grep qwen2.5:3b
```

## Run

```bash
cp -n .env.example .env
# set:
#   NETOSIS_LLM_MODE=qwen
#   NETOSIS_LLM_BASE_URL=http://127.0.0.1:11434/v1
#   NETOSIS_LLM_MODEL=qwen2.5:3b

source .venv/bin/activate
python scripts/ssh_honeypot.py --port 2222 --bind 0.0.0.0
```

## Client test

```bash
ssh admin@<server-ip> -p 2222
# password: admin123

pwd
ls
ip route
man corp_backup.sh    # RAG + Qwen path (unknown command)
exit
```

Telemetry lands in `data/telemetry.jsonl`; graph in `data/attack_graph.json`.

## Firewall

Open TCP/2222 only from your laptop / attacker VLAN, e.g. firewalld/nft temporarily.
Never expose management `172.30.226.0/24` services as the bait surface.
