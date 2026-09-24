# Corporate Network Topology

This document outlines the internal VLAN layout for NetOsis Enterprise.

## VLAN Segments
*   **VLAN 10 (Finance):** `192.168.10.0/24`. Strict isolation. Gateway: `192.168.10.254`. Hosts the primary PostgreSQL databases.
*   **VLAN 20 (Operations):** `192.168.20.0/24`. Gateway: `192.168.20.254`. Contains internal operational tooling and jump boxes.
*   **VLAN 30 (Enterprise/Web):** `192.168.30.0/24`. Gateway: `192.168.30.254`. General employee services and intranets.
*   **VLAN 40 (SOC):** `192.168.40.0/24`. Security operations and monitoring.
*   **Management:** `172.30.226.0/24`. **RESTRICTED.** Do not expose to general subnets.

## Routing
Routing is handled by the core OPNsense firewall. Traffic between Finance and Enterprise requires strict access control list (ACL) approval.
