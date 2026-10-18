# Service Accounts & Backup Registry

## Service Accounts

* `svc_finance_backup` — backup user on finance-db-01. Home: `/home/svc_finance_backup/`.
  Nightly target: `/var/backups/finance/fin_db_q3_backup.sql.gz`.
* `svc_ops_sync` — rsync service on ops-app-01. Home: `/home/svc_ops_sync/`.
  Config: `/etc/ops_sync/rsync.conf`.
* `svc_web_deploy` — deploy key owner for ent-web-01. Home: `/home/svc_web_deploy/`.

## Executive & Admin Contacts

* **Eleanor Vance** (CFO) — `evance@netosis.internal` — owns finance DB backup approvals.
* **Marcus Sterling** (Lead Systems Ops) — `msterling@netosis.internal` — ERP / ops sync admin.
* **Clara Oswald** (SOC Lead) — `coswald@netosis.internal` — SIEM & incident response (VLAN 40).
* **James Whitfield** (Enterprise Admin) — `jwhitfield@netosis.internal` — enterprise web administration.

## Backup File Locations

* `/var/backups/finance/fin_q3_reconciliation_2024.csv` — ledger summary.
* `/var/backups/finance/fin_db_q3_backup.sql.gz` — compressed DB dump.
* `/var/backups/ops/system_state_snapshot.tar.gz` — ops config snapshot.
* `/var/backups/ops/rsync_last_run.log` — last sync timestamps.
* `/home/admin/notes.txt` on ent-web-01 — change-window notes.

## Server addresses

* finance-db-01 `192.168.10.10`
* ops-app-01 `192.168.20.10`
* ent-web-01 `192.168.30.10`
