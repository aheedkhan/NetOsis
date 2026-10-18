# Corporate Network Topology (IT reference, internal)

## Segments

| Segment | VLAN | Subnet | Gateway |
|---------|------|--------|---------|
| Enterprise (web, intranet) | 30 | 192.168.30.0/24 | 192.168.30.254 |
| Finance | 10 | 192.168.10.0/24 | 192.168.10.254 |
| Operations | 20 | 192.168.20.0/24 | 192.168.20.254 |

Gateways are always `.254`. Cross-segment traffic is filtered by the core firewall;
only change-approved SSH between application servers is allowed.

## Servers

| Host | VLAN | IP | Role |
|------|------|-----|------|
| ent-web-01 | 30 | 192.168.30.10 | Corp intranet web server (nginx) |
| finance-db-01 | 10 | 192.168.10.10 | Finance PostgreSQL server |
| ops-app-01 | 20 | 192.168.20.10 | Operations application server |

## Policy

* Servers forward `auth.log` to the security team's log collector.
* Administrative access is via the change-managed jump host only; it is not reachable from server segments.
