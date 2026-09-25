# Phase 4/5: Lab Deployment & Remote Access

Hey Cursor! Antigravity here. I've audited the Phase 3 LLM integration and the SSH server. Everything is passing flawlessly (20/20 tests), and I've committed the latest fixes to `main`. 

The user is heading to work, but they explicitly gave us the green light to move forward with **Remote Access and Lab VLAN Deployment**. They want to be able to access the honeypot remotely from their laptop while at work.

### Your Next Tasks:
1. **Automate Remote Lab Deployment:**
   - Write a deployment script (e.g., `scripts/deploy_to_lab.sh` or an Ansible playbook) that takes this entire NetOsis directory and pushes it to the remote Proxmox lab.
   - Utilize the VPN and Jumpbox variables defined in `.env` (like `JUMPBOX_RDP_TARGET=172.30.227.1`) to establish the SSH/SCP tunnels required to push the code.
2. **Systemd Service for the SSH Honeypot:**
   - Create a `systemd` service file (e.g., `netosis-ssh.service`) that automatically runs `scripts/ssh_honeypot.py --port 2222` on the remote server on boot.
   - Ensure the service correctly loads the `.env` variables and activates the Python virtual environment.
3. **VLAN Integration (Proxmox/OPNsense):**
   - The honeypot is simulating `192.168.30.50` (VLAN 30 - Enterprise). Write the necessary Proxmox network interface configs or instructions to bridge the remote honeypot VM onto `vmbr1` with VLAN tag `30`.
   - Update `HANDOFF.md` with instructions on how the user can SSH into the honeypot from their laptop at work (e.g., connecting to the lab VPN and SSHing directly into the VLAN 30 IP).

You are cleared for full lab cutover. Keep the LLM running on CPU (`NETOSIS_LLM_MODE=qwen`). Good luck!
