# Listening services & banners (for RAG / shell questions about recon)

## This host (ent-web-01 / enterprise web)

* SSH: OpenSSH_8.9p1 Ubuntu-3ubuntu0.10 on TCP **22** (lab front-door may be published as WAN:22 → host:2222).
* HTTP: nginx on TCP **80** (Corp Intranet).
* Banner example attackers see on SSH: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`

## What nmap means here

External `nmap` against the lab IP hits the **real honeypot listener** (Paramiko presenting as OpenSSH).  
Service/version lines are **not** invented by the LLM.

Inside an SSH session, if the attacker types `nmap`, that command is usually **not installed**; replies come from the **LLM fallback** constrained by this evidence and host YAML (and are marked `[llm]` in demo mode).

## Related hosts

* finance-db-01: postgresql **5432**, ssh **22** (often revealed only after deception policy D01).
* Enterprise jumpbox (real): separate from this decoy — do not invent management IPs.
