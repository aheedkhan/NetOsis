# NetOsis

Resource-efficient adaptive deception / high-interaction honeypot environment
for an FYP lab. Attackers interact with believable services; most apparent hosts
are virtual state, not one VM each. Telemetry drives MITRE ATT&CK mapping, a
dynamic attack graph, and deterministic policy that adapts deception.

## Status

Fresh project. First goal: a thin vertical slice (no LLM controller):

```text
login → fake shell (pwd / ls / cat / whoami)
  → telemetry → ATT&CK → attack graph
  → one policy action (D01: expose fake host)
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional; paths for lab scripts

# Interactive fake shell
python -m deception.runtime.cli

# End-to-end demo (shell → telemetry → ATT&CK → graph → D01)
python -m scripts.demo_vertical_slice

# Tests
pytest -q
```

## Layout (as needed)

| Path | Role |
|------|------|
| `config/network/` | Locked VLAN / IP model |
| `deception/` | Virtual hosts + command engine + runtime |
| `telemetry/` | Event schema + JSONL store |
| `mitre/` | Behavior → ATT&CK mapping |
| `attack_graph/` | Dynamic graph updates |
| `policy/` | Baseline risk → deception actions |
| `docs/` | Network, employee VMs, architecture notes |
| `scripts/lab-access/` | VPN + FreeRDP wrappers (no secrets in Git) |

See also: [docs/rag.md](docs/rag.md), [docs/llm-local.md](docs/llm-local.md), [docs/ssh-honeypot.md](docs/ssh-honeypot.md).

## Lab access

Secrets stay under `/home/mania/Documents/server/` on the workstation.
Use `scripts/lab-access/` after copying `.env.example` → `.env`.

## Non-goals (early phases)

GNN, disposable malware sandbox, Kubernetes, cloning the old GitHub NetOsis,
automatic Proxmox/OPNsense changes.
