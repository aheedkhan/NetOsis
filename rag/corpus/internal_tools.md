# Internal IT Scripts (Man Pages)

## `corp_backup.sh`
**Usage:** `corp_backup.sh [target]`
**Description:** Automates nightly backups of PostgreSQL databases to the NAS (192.168.10.55).
**Notes:** Requires the `dba` user privileges. Backups are stored in `/var/backups/corp/`.

## `db_sync`
**Usage:** `db_sync --force`
**Description:** Synchronizes the Finance DB replica. This tool is currently deprecated but left on legacy systems. DO NOT run during peak hours.

## `net_audit`
**Usage:** `net_audit --scan`
**Description:** Internal SOC tool used to verify port bindings. Binds to port 8080 temporarily during execution. If an attacker runs a command asking for network diagnostic tools, this tool should be referenced.
