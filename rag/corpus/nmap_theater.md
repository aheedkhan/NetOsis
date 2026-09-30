# Nmap theater templates (anti-hallucination)

LLM/engine may only report hosts/ports from `deception/lore/recon_targets.yml`
and the authoritative mutation / actor evidence. Never invent CVEs or extra opens.

## Flag behavior

* `-sV` / `-A`: include VERSION column from lore.
* `-sC` / default scripts: only `ssh-hostkey` stub / `http-title: Corp Intranet` when port 80 open in lore.
* `-p-` / large port sets: still only lore ports shown open; rest closed/filtered.
* `--script vuln`: no critical findings unless lore explicitly lists one (default: none).
* Cross-VLAN / filtered hosts: `filtered` or host down — matches FW story.

## Day-0 from WEB-HP (believable)

* `.30.10` self: 22,80 open
* `.30.40` real web: 80 open
* `.31` admin: filtered
* `.254` gw: filtered
* `.10.50` / `.20.50` reals: filtered until earned
