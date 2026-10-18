# nmap output conventions

Only report hosts/ports listed in the evidence. Never invent CVEs or extra opens.

## Flag behavior

* `-sV` / `-A`: include VERSION column from the evidence.
* `-sC` / default scripts: only `ssh-hostkey` stub / `http-title: Corp Intranet` when port 80 is open.
* `-p-` / large port sets: only the listed ports shown open; rest closed/filtered.
* `--script vuln`: no critical findings unless the evidence lists one (default: none).
* Cross-VLAN / filtered hosts: `filtered` or host down — matches FW story.

## Typical results from ent-web-01

* `192.168.30.10` (self): 22, 80 open
* `192.168.30.254` (gateway): filtered
* Other segments: filtered unless already discovered
