# NetOsis Enterprise Fake Accounts & Backup Registry
# FakeNameGenerator-style personas for RAG (not real people).

## Service Accounts

* `svc_finance_backup` — backup user on finance-db lore. Home: `/home/svc_finance_backup/`.
  Nightly target: `/var/backups/finance/fin_db_q3_backup.sql.gz`.
* `svc_ops_sync` — rsync service on ops lore. Home: `/home/svc_ops_sync/`.
  Config: `/etc/ops_sync/rsync.conf`.
* `svc_web_deploy` — deploy key owner for ent-web decoy. Home: `/home/svc_web_deploy/`.

## Executive & Admin Personas (synthetic)

* **Eleanor Vance** (CFO) — `evance@netosis.internal` — owns finance DB backup approvals.
* **Marcus Sterling** (Lead Systems Ops) — `msterling@netosis.internal` — ERP / ops sync admin.
* **Clara Oswald** (SOC Lead) — `coswald@netosis.internal` — SIEM & incident response (VLAN 40).
* **James Whitfield** (Enterprise Admin) — `jwhitfield@netosis.internal` — uses ENT-JUMP-01.

## Backup File Structures (lore paths for cat/ls on HPs)

* `/var/backups/finance/fin_q3_reconciliation_2024.csv` — fake ledger summary.
* `/var/backups/finance/fin_db_q3_backup.sql.gz` — compressed DB dump lore (do not invent rows beyond evidence).
* `/var/backups/ops/system_state_snapshot.tar.gz` — ops config snapshot lore.
* `/var/backups/ops/rsync_last_run.log` — last sync timestamps.
* `/home/admin/notes.txt` on WEB-HP may hint at finance-db after change window.

## Network reminders for LLM

* FIN-HP `192.168.10.10`, real FINANCE-DB `192.168.10.50` (filtered from HHP until earned).
* OPS-HP `192.168.20.10`, real OPS-APP `192.168.20.50`.
* WEB-HP `192.168.30.10`, ENT-ADMIN `192.168.30.31` filtered, ENT-WEB `192.168.30.40` http may be open.
