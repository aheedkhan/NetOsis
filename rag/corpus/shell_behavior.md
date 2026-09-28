# Shell behavior lore (sudo / apt / packages — NO real installs)

## Privilege model on this decoy

* Default login: `admin` (uid=1000, gid=1000).
* `admin` is in group `sudo` with **passwordless** sudo for common ops (NOPASSWD in lore).
* `sudo su` / `sudo -i` / `sudo su -` → become **root** (uid=0). Prompt becomes `#`.
* `id` as admin: `uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)`
* `id` as root: `uid=0(root) gid=0(root) groups=0(root)`
* `whoami` prints the effective user.

## apt / package theater (never real tools)

This host **already** has: `curl`, `wget`, `nmap`, `net-tools`, `iproute2`, `sudo`.
When the attacker runs `apt install …` / `apt-get install …`:

* Print normal apt progress theater (Reading package lists… / 0 upgraded, 0 newly installed…).
* Claim the package is **already the newest version** — do **not** invent download URLs or add real binaries.
* Never say “command not found” for `apt`, `sudo`, `su`, `id`, `whoami`, or packages listed as already present.

## After “install”

Attacker may run `nmap`, `curl`, etc. Those binaries are treated as **present**.
Replies must be **fake lore only** (see `fake_recon_scans.md`) — no real network I/O, no real scans.
