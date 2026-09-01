#!/usr/bin/env python3
"""
Generates the static content served by the NexusCorp org hosts.

Kept as a generator rather than eight hand-written directories so the fictional
company stays internally consistent: one employee list, one address, one set of
project names, referenced from every host. An adversary who reads the marketing
site and then the intranet must find the same people in both, because the first
thing a careful operator does is cross-check.
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent

COMPANY = "NexusCorp Industrial Systems"
DOMAIN = "nexuscorp.example"
ADDRESS = "Building 4, Harbour Technology Park, Rotterdam"

STAFF = [
    ("Marieke de Vries", "Chief Technology Officer", "m.devries"),
    ("Tomasz Wójcik", "Head of Platform Engineering", "t.wojcik"),
    ("Priya Raghunathan", "Lead SCADA Engineer", "p.raghunathan"),
    ("Daniel Osei", "Infrastructure Engineer", "d.osei"),
    ("Sofia Marchetti", "Financial Controller", "s.marchetti"),
    ("Jan Bakker", "IT Service Desk", "j.bakker"),
]

CSS = """
:root{--ink:#12202e;--muted:#5d6b7a;--line:#d8e0e8;--brand:#0b5c8a;--bg:#f6f8fa}
*{box-sizing:border-box}
body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
header{background:#fff;border-bottom:1px solid var(--line)}
.wrap{max-width:960px;margin:0 auto;padding:0 24px}
.bar{display:flex;align-items:center;justify-content:space-between;height:64px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:-.2px}
.logo span{display:grid;place-items:center;width:30px;height:30px;border-radius:6px;background:var(--brand);color:#fff;font-size:15px}
nav a{color:var(--muted);text-decoration:none;margin-left:22px;font-size:14px}
nav a:hover{color:var(--brand)}
.hero{background:linear-gradient(180deg,#fff,var(--bg));padding:56px 0 40px;border-bottom:1px solid var(--line)}
h1{font-size:32px;margin:0 0 12px;letter-spacing:-.5px}
h2{font-size:19px;margin:34px 0 12px}
.lede{color:var(--muted);font-size:17px;max-width:620px;margin:0}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin:26px 0}
.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:18px}
.card h3{margin:0 0 6px;font-size:15px}
.card p{margin:0;color:var(--muted);font-size:14px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
th{background:#eef2f6;font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:0}
footer{margin-top:48px;padding:26px 0;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.login{max-width:360px;margin:60px auto;background:#fff;border:1px solid var(--line);border-radius:10px;padding:30px}
.login h1{font-size:20px;text-align:center}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 5px}
input{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:6px;font-size:14px}
button{width:100%;margin-top:20px;padding:10px;background:var(--brand);color:#fff;border:0;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
.note{margin-top:16px;color:var(--muted);font-size:12px;text-align:center}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
.ok{background:#e3f3ea;color:#1d6b45}.warn{background:#fdf0dd;color:#8a5a12}
"""


def page(title, body, nav=True):
    links = ""
    if nav:
        links = ('<nav><a href="/">Home</a><a href="/about.html">About</a>'
                 '<a href="/solutions.html">Solutions</a><a href="/contact.html">Contact</a></nav>')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{CSS}</style></head><body>
<header><div class="wrap bar">
<div class="logo"><span>N</span> NexusCorp</div>{links}
</div></header>
{body}
<div class="wrap"><footer>&copy; 2026 {COMPANY} &middot; {ADDRESS}<br>
KvK 55219004 &middot; <a href="mailto:info@{DOMAIN}" style="color:var(--muted)">info@{DOMAIN}</a></footer></div>
</body></html>"""


def write(host, name, html):
    d = ROOT / host
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------- www01 ----
write("www01", "index.html", page("NexusCorp Industrial Systems", f"""
<div class="hero"><div class="wrap">
<h1>Control systems for critical infrastructure</h1>
<p class="lede">NexusCorp designs, deploys and maintains industrial control and
telemetry platforms for port authorities, water boards and energy operators
across northern Europe.</p>
</div></div>
<div class="wrap">
<div class="grid">
<div class="card"><h3>SCADA integration</h3><p>Vendor-neutral integration across Siemens, ABB and Schneider estates.</p></div>
<div class="card"><h3>Remote telemetry</h3><p>Hardened RTU fleets with end-to-end monitoring and 24/7 response.</p></div>
<div class="card"><h3>Compliance</h3><p>IEC 62443 and NIS2 readiness assessments and remediation programmes.</p></div>
</div>
<h2>Recent work</h2>
<table>
<tr><th>Client</th><th>Programme</th><th>Year</th></tr>
<tr><td>Port of Rotterdam Authority</td><td>Lock telemetry modernisation</td><td>2025</td></tr>
<tr><td>Waterschap Hollandse Delta</td><td>Pumping station SCADA refresh</td><td>2025</td></tr>
<tr><td>NordEnergi A/S</td><td>Substation remote access programme</td><td>2024</td></tr>
</table>
<h2>Contact</h2>
<p class="lede">General enquiries <code>info@{DOMAIN}</code> &middot; Support
<code>servicedesk@{DOMAIN}</code> &middot; +31 10 555 0142</p>
</div>"""))

write("www01", "about.html", page("About — NexusCorp", f"""
<div class="wrap"><h1 style="margin-top:36px">About NexusCorp</h1>
<p class="lede">Founded in 2009, NexusCorp employs 240 people across Rotterdam,
Antwerp and Aarhus.</p>
<h2>Leadership</h2>
<table><tr><th>Name</th><th>Role</th><th>Contact</th></tr>
""" + "".join(
    f"<tr><td>{n}</td><td>{r}</td><td class='mono'>{e}@{DOMAIN}</td></tr>"
    for n, r, e in STAFF[:4]
) + "</table></div>"))

write("www01", "solutions.html", page("Solutions — NexusCorp", """
<div class="wrap"><h1 style="margin-top:36px">Solutions</h1>
<div class="grid">
<div class="card"><h3>NexusView</h3><p>Operator HMI and historian platform.</p></div>
<div class="card"><h3>NexusLink</h3><p>Secure RTU-to-control-centre transport.</p></div>
<div class="card"><h3>NexusGuard</h3><p>OT network monitoring and anomaly detection.</p></div>
</div></div>"""))

write("www01", "contact.html", page("Contact — NexusCorp", f"""
<div class="wrap"><h1 style="margin-top:36px">Contact</h1>
<p class="lede">{ADDRESS}</p>
<table><tr><th>Team</th><th>Address</th></tr>
<tr><td>General</td><td class="mono">info@{DOMAIN}</td></tr>
<tr><td>Service desk</td><td class="mono">servicedesk@{DOMAIN}</td></tr>
<tr><td>Security</td><td class="mono">security@{DOMAIN}</td></tr>
</table></div>"""))

write("www01", "robots.txt", "User-agent: *\nDisallow: /internal/\nDisallow: /backup/\n")

# --------------------------------------------------------------- mail01 ----
write("mail01", "index.html", page("NexusCorp Webmail", f"""
<div class="login">
<h1>NexusCorp Webmail</h1>
<form method="post" action="/login">
<label for="u">Email address</label>
<input id="u" name="username" type="text" placeholder="name@{DOMAIN}" autocomplete="username">
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<p class="note">Access is restricted to authorised personnel.<br>
Service desk: +31 10 555 0142</p>
</div>""", nav=False))

# ---------------------------------------------------------------- vpn01 ----
write("vpn01", "index.html", page("NexusCorp Secure Access", """
<div class="login">
<h1>Secure Access Portal</h1>
<form method="post" action="/auth">
<label for="u">Username</label><input id="u" name="username" type="text" autocomplete="username">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<label for="t">Token code</label><input id="t" name="token" type="text" inputmode="numeric" placeholder="6 digits">
<button type="submit">Connect</button>
</form>
<p class="note">Appliance build 9.4.2-b117<br>Two-factor authentication required.</p>
</div>""", nav=False))

# ----------------------------------------------------------------- dc01 ----
write("dc01", "index.html", page("DC01 — Directory Services", f"""
<div class="wrap"><h1 style="margin-top:36px">DC01 <span class="badge ok">healthy</span></h1>
<p class="lede">Domain controller for <code>NEXUSCORP</code> &middot; site Rotterdam-HQ</p>
<table><tr><th>Service</th><th>Port</th><th>State</th></tr>
<tr><td>LDAP</td><td class="mono">389</td><td><span class="badge ok">listening</span></td></tr>
<tr><td>LDAPS</td><td class="mono">636</td><td><span class="badge ok">listening</span></td></tr>
<tr><td>Kerberos</td><td class="mono">88</td><td><span class="badge ok">listening</span></td></tr>
<tr><td>SMB</td><td class="mono">445</td><td><span class="badge ok">listening</span></td></tr>
<tr><td>DNS</td><td class="mono">53</td><td><span class="badge ok">listening</span></td></tr>
</table>
<h2>Directory</h2>
<table><tr><th>Account</th><th>Display name</th><th>Group</th></tr>
""" + "".join(
    f"<tr><td class='mono'>NEXUSCORP\\{e}</td><td>{n}</td><td>{'Domain Admins' if i < 2 else 'Domain Users'}</td></tr>"
    for i, (n, r, e) in enumerate(STAFF)
) + "</table></div>"))

# ----------------------------------------------------------------- fs01 ----
write("fs01", "index.html", page("FS01 — File Services", """
<div class="wrap"><h1 style="margin-top:36px">FS01 <span class="badge ok">healthy</span></h1>
<p class="lede">Departmental file shares &middot; 14.2 TB of 20 TB used</p>
<table><tr><th>Share</th><th>Path</th><th>Access</th></tr>
<tr><td class="mono">ENGINEERING</td><td class="mono">D:\\shares\\engineering</td><td>Domain Users (RW)</td></tr>
<tr><td class="mono">FINANCE</td><td class="mono">D:\\shares\\finance</td><td>Finance (RW)</td></tr>
<tr><td class="mono">PROJECTS</td><td class="mono">D:\\shares\\projects</td><td>Domain Users (RO)</td></tr>
<tr><td class="mono">BACKUP$</td><td class="mono">E:\\backup</td><td>Domain Admins</td></tr>
</table></div>"""))

# ---------------------------------------------------------------- erp01 ----
write("erp01", "index.html", page("NexusCorp Intranet", f"""
<div class="wrap"><h1 style="margin-top:36px">Intranet</h1>
<p class="lede">Internal only. Do not share links outside the corporate network.</p>
<div class="grid">
<div class="card"><h3>Expenses</h3><p>Q3 submissions close 30 September.</p></div>
<div class="card"><h3>Change calendar</h3><p>Substation refresh window: 12–14 Oct.</p></div>
<div class="card"><h3>Service desk</h3><p>ext. 4400 &middot; {STAFF[5][2]}@{DOMAIN}</p></div>
</div>
<h2>Announcements</h2>
<table><tr><th>Date</th><th>Notice</th></tr>
<tr><td class="mono">2026-08-24</td><td>Password policy changes to 14 characters on 1 October.</td></tr>
<tr><td class="mono">2026-08-11</td><td>Legacy <code>dev</code> host is scheduled for decommissioning.</td></tr>
<tr><td class="mono">2026-07-30</td><td>VPN appliance upgraded to 9.4.2.</td></tr>
</table></div>"""))

# ----------------------------------------------------------------- db01 ----
write("db01", "index.html", page("DB01 — Database Services", """
<div class="wrap"><h1 style="margin-top:36px">DB01 <span class="badge ok">healthy</span></h1>
<p class="lede">Datacenter tier &middot; not reachable from the deception zone</p>
<table><tr><th>Instance</th><th>Engine</th><th>State</th></tr>
<tr><td class="mono">NEXUS_ERP</td><td>PostgreSQL 16</td><td><span class="badge ok">online</span></td></tr>
<tr><td class="mono">NEXUS_HIST</td><td>PostgreSQL 16</td><td><span class="badge ok">online</span></td></tr>
</table></div>"""))

# ---------------------------------------------------------------- bkp01 ----
write("bkp01", "index.html", page("BKP01 — Backup", """
<div class="wrap"><h1 style="margin-top:36px">BKP01 <span class="badge warn">degraded</span></h1>
<p class="lede">Last successful full backup 2026-08-29 02:14 UTC</p>
<table><tr><th>Job</th><th>Target</th><th>Result</th></tr>
<tr><td>Nightly full</td><td class="mono">FS01</td><td><span class="badge ok">ok</span></td></tr>
<tr><td>Nightly full</td><td class="mono">DB01</td><td><span class="badge ok">ok</span></td></tr>
<tr><td>Weekly offsite</td><td class="mono">tape-lib-01</td><td><span class="badge warn">retry</span></td></tr>
</table></div>"""))

print("generated org site content:")
for d in sorted(ROOT.iterdir()):
    if d.is_dir():
        print(f"  {d.name}: {', '.join(sorted(p.name for p in d.iterdir()))}")
