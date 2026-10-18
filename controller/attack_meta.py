"""ATT&CK tactic lookup for the techniques NetOsis can emit (Enterprise matrix)."""

from __future__ import annotations

TACTICS: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# technique id -> (name, tactic). Names mirror mitre/mappings/command_behaviors.yml.
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1518": ("Software Discovery", "Discovery"),
    "T1005": ("Data from Local System", "Collection"),
    "T1074.001": ("Data Staged: Local Data Staging", "Collection"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1070.002": ("Indicator Removal: Clear Linux Logs", "Defense Evasion"),
    "T1222.002": ("File Permissions Modification: Linux", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1003.008": ("OS Credential Dumping: /etc/shadow", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1552.003": ("Bash History", "Credential Access"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1548.001": ("Setuid and Setgid", "Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
}


def lookup(technique: str, fallback_name: str | None = None) -> tuple[str, str]:
    name, tactic = TECHNIQUES.get(technique, (fallback_name or technique, "Discovery"))
    return name, tactic
