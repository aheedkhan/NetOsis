"""ATT&CK and MITRE Engage mappings — intelligence plane v1."""

from __future__ import annotations

from typing import Any

# dataset → ATT&CK technique (primary)
DATASET_TECHNIQUE: dict[str, tuple[str, str, str, str]] = {
  # dataset: (technique_id, technique_name, tactic_id, tactic_name)
    "cybersnare.ssh.auth": ("T1078", "Valid Accounts", "TA0001", "Initial Access"),
    "cybersnare.http.request": ("T1078", "Valid Accounts", "TA0001", "Initial Access"),
    "cybersnare.shell.command": ("T1059", "Command and Scripting Interpreter", "TA0002", "Execution"),
    "cybersnare.shell.vm_check": ("T1497", "Virtualization/Sandbox Evasion", "TA0005", "Defense Evasion"),
    "cybersnare.shell.proc_read": ("T1007", "System Service Discovery", "TA0007", "Discovery"),
    "cybersnare.shell.file_access": ("T1083", "File and Directory Discovery", "TA0007", "Discovery"),
    "cybersnare.sinkhole.dns": ("T1071", "Application Layer Protocol", "TA0011", "Command and Control"),
    "cybersnare.sinkhole.http": ("T1105", "Ingress Tool Transfer", "TA0011", "Command and Control"),
    "cybersnare.zeek.conn": ("T1595", "Active Scanning", "TA0043", "Reconnaissance"),
    "cybersnare.zeek.ssh": ("T1021", "Remote Services", "TA0008", "Lateral Movement"),
    "cybersnare.zeek.ssl": ("T1040", "Network Sniffing", "TA0006", "Credential Access"),
    "cybersnare.zeek.http": ("T1595", "Active Scanning", "TA0043", "Reconnaissance"),
    "cybersnare.decision.transition": ("T1598", "Phishing for Information", "TA0043", "Reconnaissance"),
}

ENGAGE_BY_DATASET: dict[str, str] = {
    "cybersnare.ssh.auth": "EAC0005",
    "cybersnare.http.request": "EAC0003",
    "cybersnare.shell.command": "EAC0005",
    "cybersnare.sinkhole.dns": "EAC0003",
    "cybersnare.sinkhole.http": "EAC0003",
    "cybersnare.decision.transition": "EAC0004",
    "cybersnare.zeek.conn": "EAC0003",
    "cybersnare.shell.file_access": "EAC0005",
}


def enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    """Add ATT&CK/Engage if missing."""
    ds = (event.get("event") or {}).get("dataset") or ""
    threat = event.setdefault("threat", {})
    if ds in DATASET_TECHNIQUE:
        tid, tname, tacid, tacname = DATASET_TECHNIQUE[ds]
        tech = threat.setdefault("technique", {})
        tac = threat.setdefault("tactic", {})
        if not tech.get("id"):
            tech["id"] = tid
            tech["name"] = tname
        if not tac.get("id"):
            tac["id"] = tacid
            tac["name"] = tacname
    dec = event.setdefault("deception", {})
    if not dec.get("engage_activity") and ds in ENGAGE_BY_DATASET:
        dec["engage_activity"] = ENGAGE_BY_DATASET[ds]
    return event
