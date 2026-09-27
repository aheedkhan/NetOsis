# Ops

Lab deployment helpers. **No automatic Proxmox/OPNsense mutation.**

| Path | Role |
|------|------|
| `systemd/netosis-ssh.service` | systemd unit for SSH honeypot |
| `proxmox/PROPOSED_VLAN30_HONEYPOT.md` | Proposed VM NIC / netplan (manual approve) |

Deploy flow: `scripts/deploy_to_lab.sh` → `scripts/lab-bootstrap-remote.sh`.
Remote use: `docs/remote-access.md`.
