# Corporate Network Topology

This document outlines the internal VLAN layout for NetOsis Enterprise.

## VLAN Segments
*   **VLAN 10 (Finance):** `192.168.10.0/24`. Gateway: `192.168.10.254`. Contains Finance Employees and Finance Honeypots.
*   **VLAN 20 (Operations):** `192.168.20.0/24`. Gateway: `192.168.20.254`. Contains Operations Employees and Ops Honeypots.
*   **VLAN 30 (Enterprise):** `192.168.30.0/24`. Gateway: `192.168.30.254`. Server infrastructure only. Contains the real Jumpbox, real Enterprise Servers, and Enterprise Honeypots.
*   **VLAN 40 (SOC):** `192.168.40.0/24`. Gateway: `192.168.40.254`. Contains the NetOsis Controller, LLM Engine, and Wazuh server for monitoring employees.
*   **Management:** `172.30.226.0/24`. **RESTRICTED.** Do not expose to general subnets.

## Routing
Routing is handled by the core OPNsense firewall. Traffic between Finance and Enterprise requires strict access control list (ACL) approval.
