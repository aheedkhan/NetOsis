# Local lab: the whole NetOsis architecture on one PC, no server

Status: **plan, not implemented yet** (written 2026-11-12). This is the next job.

## Goal

Rebuild the real lab on a single Linux PC with KVM/libvirt: a real OPNsense firewall,
the four zones, three honeypots, the SOC VM and an outside attacker. It keeps the **same IPs, names
and firewall rules** as the server lab (`docs/DEPLOY-lab.md`). As a result:

* the code, `.env` files, node names and `lab-verify.sh` checks work unchanged;
* moving back to a server later only swaps the transport (`pct` ↔ libvirt), not the design;
* the full attack story can be demoed offline: Kali → FW WAN:22 → ent-web-01 → pivot to finance-db-01 → SOC.

Recommended host: **16 GB RAM** free, 8 threads, about 80 GB of disk. The dev PC used so far has 62 GB, 16 threads, podman, virsh and qemu.
On Fedora: `sudo dnf install @virtualization virt-install libguestfs-tools`, then `sudo systemctl enable --now libvirtd`.

## Target topology

```
                      host PC (KVM/libvirt)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  nl-wan 172.30.227.0/24 (NAT to the Internet via the host, .254)          │
  │     ├─ kali            172.30.227.50   attacker, OUTSIDE the firewall     │
  │     └─ opnsense WAN    172.30.227.100  = the lab "public IP"              │
  │                                                                          │
  │  opnsense (one NIC per zone, routes + filters everything below)          │
  │     ├─ nl-mgmt 192.168.1.0/24   FW .1   host .10 (plays the Jbox)         │
  │     ├─ nl-fin  192.168.10.0/24  FW .254 finance-db-01 .10                 │
  │     ├─ nl-ops  192.168.20.0/24  FW .254 ops-app-01   .10                  │
  │     ├─ nl-ent  192.168.30.0/24  FW .254 ent-web-01   .10                  │
  │     └─ nl-soc  192.168.40.0/24  FW .254 soc          .31                  │
  └──────────────────────────────────────────────────────────────────────────┘
```

| Real lab (Proxmox) | Local equivalent |
|---|---|
| vmbr0 tag 227 (FW WAN segment) | libvirt NAT network `nl-wan`, host at `172.30.227.254` |
| vmbr1 trunk + VLANs 10/20/30/40 + untagged mgmt | five **isolated** libvirt networks; OPNsense gets one NIC per zone (no tagging) |
| VM101 OPNsense | VM `nl-opnsense` (OPNsense ISO, 2 vCPU, 3 GB) |
| VM100 Jbox (`192.168.1.10`) | the host itself, which has an IP **only** on `nl-mgmt` |
| VM103 SOC | VM `nl-soc`, Ubuntu 24.04 cloud image, 4 vCPU, 8 GB (+ Ollama) |
| CT102/104/105 | VMs `nl-ent`, `nl-fin`, `nl-ops`: Ubuntu 24.04 cloud images, 1 vCPU, 1 GB each |
| VM106 Kali | VM `nl-kali`: the Kali cloud/qemu image, or a Debian VM with nmap + openssh-client |
| `pct push` / `pct exec` | `virt-copy-in` plus qemu-guest-agent (`virsh` guest exec), see L5 |

One NIC per zone is used instead of a VLAN trunk because it is simpler and gives the same L3 behaviour
(OPNsense filters all inter-zone traffic). For a faithful trunk you can still use a Linux bridge with
`vlan_filtering=1` and libvirt `<portgroup>`/`<vlan trunk>`. That is optional and not needed.

### The one rule that must not be broken

The host must have **no IP on `nl-fin`, `nl-ops`, `nl-ent` or `nl-soc`**: define these networks with
no `<ip>` element and no `<forward>`. If the host had an address on them, it would route around
OPNsense and the isolation would be fake. The host is on `nl-mgmt` only, where it plays the Jbox, and on `nl-wan` as the upstream gateway.
Kali must not reach `nl-mgmt`. It can't, because it is on `nl-wan` and only OPNsense's WAN is there.

## Tasks (implement in this order; each has a "done when")

Put everything under `scripts/local-lab/`, idempotent and re-runnable, with bash plus small Python where needed.
No secrets in the repo: generated keys and passwords go in `~/.local/share/netosis-lab/` (mode 600).

**L1. Networks** (`scripts/local-lab/networks.sh up|down`)
* Write the six libvirt network XMLs (`scripts/local-lab/net/*.xml`) and `virsh net-define` / `net-start` / `net-autostart` them.
* `nl-wan` is NAT with host IP `172.30.227.254`, no DHCP.
* `nl-mgmt` is isolated with host IP `192.168.1.10/24`.
* The other four have no IP and no forward.

*Done when* `ip -br a` on the host shows addresses only on the `nl-wan` and `nl-mgmt` bridges.

**L2. OPNsense VM** (`scripts/local-lab/opnsense.sh`)
* `virt-install` from the OPNsense ISO with six virtio NICs in this order: wan, mgmt, fin, ops, ent, soc.
* The installer is interactive and done once by the user. Generate the config to import so nothing is clicked rule by rule: `scripts/local-lab/opnsense-config.xml.tmpl`.
* That config contains:
  * the interfaces and IPs above;
  * WAN gateway `172.30.227.254`;
  * the GUI and SSH on mgmt only;
  * the WAN port forward `tcp/22 → 192.168.30.10:2222`;
  * **exactly** the rule table of `docs/DEPLOY-lab.md` §4, with every zone ending in block + log;
  * a disabled "install window" rule per honeypot zone (80/443/53 out) for L4.
* The user imports it once (System → Configuration → Backups) and changes the root password.

*Done when*:
* `https://192.168.1.1` opens from the host;
* the WAN answers only on 22;
* the zones can't reach each other except through the listed rules.

**L3. Guest images** (`scripts/local-lab/guests.sh up|down`)
* Download the Ubuntu 24.04 cloud image once into `/var/lib/libvirt/images/`, then make qcow2 overlays per guest.
* Install each guest with `virt-install --import --cloud-init` using `user-data` and `network-config` files generated per guest:
  * static IP and gateway `.254`;
  * DNS = the FW;
  * hostname = the node name;
  * a `netosis` admin user with the host's SSH key;
  * `qemu-guest-agent` enabled.
* Give the SOC VM 8 GB; give each honeypot 1 GB.
* Kali goes on `nl-wan` at `172.30.227.50`.

*Done when* all guests boot, and each pings its own gateway and nothing it shouldn't (check it against the §4 table).

**L4. SOC install**
* Turn on the FW install-window rule for the SOC zone (it may keep Internet access for Ollama model pulls).
* Copy the repo in with `git archive | virt-copy-in` or the guest agent, as L5 does.
* Run `scripts/soc-dashboard-setup.sh` inside.
* Install Ollama and pull `qwen2.5:1.5b`. The local CPU has AVX, so bigger models are fine; set `NETOSIS_LLM_MODEL` to match.
* Use `scripts/lab-verify.sh` (role soc).

*Done when* the host opens `http://192.168.40.31:8000` through the FW, and `/root/netosis-node-keys.env` exists in the SOC VM.

**L5. Local rollout** (`scripts/local-lab/rollout.sh`, the libvirt twin of `scripts/lab-rollout.sh`)
* Keep `lab-rollout.sh`'s steps and output and only swap the transport:
  * start the domain if it is off (`virsh start`);
  * push the committed code (`git archive HEAD`) with qemu-guest-agent file writes or `virt-copy-in`;
  * run `lab-bootstrap-remote.sh <profile> --key-stdin`, passing the node key on stdin;
  * run `lab-verify.sh`;
  * print the summary.
* Best design: factor `lab-rollout.sh` into a transport function set (`node_start`, `node_push`, `node_exec`) with `pct` and `virsh` implementations, selected by `--transport pct|libvirt`. Then there is one script, not two.
* The node keys come from the file written in L4. Copy it to the host as `~/.local/share/netosis-lab/node-keys.env` (600), and delete it after rollout.
* `lab-bootstrap-remote.sh` currently assumes a Proxmox CT. Check it for `pct`/CTID assumptions; `NETOSIS_NODE_CTID` can be left empty locally.
* Close the install-window rules afterwards, and run `rollout.sh --verify-only`.

*Done when* all three nodes show **online** on the System page, `lab-verify.sh` reports no FAIL on any node, and the agents listen on nothing.

**L6. End-to-end attack test** (`scripts/local-lab/e2e.sh`, run from the host, driving Kali over SSH on `nl-wan`)
* From Kali: `nmap -Pn -p- 172.30.227.100` shows **only 22 open**.
* `ssh admin@172.30.227.100` lands in the ent-web-01 fake shell. The SOC shows the session with Kali's real source IP (DNAT keeps it).
* Inside the shell, run discovery, then `ssh finance-db-01`. The pivot goes over the relay (`:2222`), and the SOC shows the lateral edge in the topology and attack graph.
* Check that Kali can't reach `192.168.40.31`, `192.168.1.1` or `172.30.227.254:22`, and that a honeypot can't reach the dashboard port 8000.

*Done when* the script prints PASS for each step. Record a short GIF for `docs/media/` if the user wants one.

Note: Kali's IP is private, so the globe shows **no arc**. That is correct (no geolocating private IPs). Do not fake one.

**L7. Docs**
* Add a "Local lab" section to `README.md` and `docs/DEPLOY-lab.md` pointing here.
* Update `CLAUDE.md` "Current state" when L1–L6 are done.

## Things to keep in mind

* **Auto-wake / power:**
  * `controller/proxmox.py` only works against Proxmox. Locally, leave the `PROXMOX_*` vars unset and keep all three honeypots running.
  * Auto-wake is simply inactive then. Check that the controller degrades quietly, not with errors.
  * Power control is the user's own work. If a local backend is wanted later, it would be a tiny host-side broker that allowlists `nl-fin`/`nl-ops`/`nl-ent` start/stop, reachable only from `192.168.40.31`. Do not build it without asking.
* **Clock:** guests must use NTP (or the host via the FW); signatures are refused beyond 90 s of drift.
* **Snapshots:** after L5, `virsh snapshot-create-as` on each guest gives a clean "reset the lab" before demos.
* **Lighter fallback:** a podman-only mode (SOC + honeypot + attacker containers) was used to test the code, but it has no real firewall. It is fine for quick dev; use the libvirt lab for anything that claims isolation.
* **Fidelity check:** the lab is correct when every row of `docs/DEPLOY-lab.md` §4 can be shown working (allowed) or blocked + logged in OPNsense's Live View.
