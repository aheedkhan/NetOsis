"""Fill a VirtualHost with a full, believable Ubuntu 22.04 system.

Host YAML only lists what is special about a host (breadcrumbs, canaries,
services). Everything an attacker checks right after login — /etc/passwd,
/etc/shadow, logs, binaries, SUID files, dotfiles, old timestamps — is
generated here, deterministically, so every session sees the same machine.
Entries already in the YAML always win.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from deception.command_engine.binaries import KNOWN_BINARIES
from deception.system import clock

if TYPE_CHECKING:
    from deception.runtime.host import VirtualHost

DEFAULT_SYSTEM: dict[str, Any] = {
    "kernel": "5.15.0-112-generic",
    "kernel_build": "#122-Ubuntu SMP Thu May 23 07:48:21 UTC 2024",
    "install_date": "2023-02-14 09:31",
    "uptime_days": 47,
    "cpu_model": "Intel(R) Xeon(R) CPU           X5650  @ 2.67GHz",
    "cpus": 2,
    "memory_mb": 3931,
    "mem_used_mb": 1180,
    "swap_mb": 2047,
    "load": [0.08, 0.11, 0.09],
    "disks": [
        {"dev": "/dev/sda2", "mount": "/", "fstype": "ext4", "size_gb": 39.0, "used_gb": 14.6},
        {"dev": "/dev/sda1", "mount": "/boot/efi", "fstype": "vfat", "size_gb": 0.5, "used_gb": 0.006},
    ],
    "mac": "bc:24:11:00:00:01",
    "admin_ips": [],
}

# System accounts every Ubuntu 22.04 server has (uid, gid, gecos, home, shell).
_SYSTEM_USERS = [
    ("root", 0, 0, "root", "/root", "/bin/bash"),
    ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
    ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
    ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
    ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
    ("games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"),
    ("man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"),
    ("lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
    ("mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"),
    ("news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"),
    ("uucp", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin"),
    ("proxy", 13, 13, "proxy", "/bin", "/usr/sbin/nologin"),
    ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
    ("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"),
    ("list", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin"),
    ("irc", 39, 39, "ircd", "/run/ircd", "/usr/sbin/nologin"),
    ("gnats", 41, 41, "Gnats Bug-Reporting System (admin)", "/var/lib/gnats", "/usr/sbin/nologin"),
    ("nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"),
    ("_apt", 100, 65534, "", "/nonexistent", "/usr/sbin/nologin"),
    ("systemd-network", 101, 102, "systemd Network Management,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("systemd-resolve", 102, 103, "systemd Resolver,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("messagebus", 103, 104, "", "/nonexistent", "/usr/sbin/nologin"),
    ("systemd-timesync", 104, 105, "systemd Time Synchronization,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("pollinate", 105, 1, "", "/var/cache/pollinate", "/bin/false"),
    ("sshd", 106, 65534, "", "/run/sshd", "/usr/sbin/nologin"),
    ("syslog", 107, 113, "", "/home/syslog", "/usr/sbin/nologin"),
    ("uuidd", 108, 114, "", "/run/uuidd", "/usr/sbin/nologin"),
    ("tcpdump", 109, 115, "", "/nonexistent", "/usr/sbin/nologin"),
    ("tss", 110, 116, "TPM software stack,,,", "/var/lib/tpm", "/bin/false"),
    ("landscape", 111, 117, "", "/var/lib/landscape", "/usr/sbin/nologin"),
    ("usbmux", 112, 46, "usbmux daemon,,,", "/var/lib/usbmux", "/usr/sbin/nologin"),
]

_SYSTEM_GROUPS = [
    ("root", 0), ("daemon", 1), ("bin", 2), ("sys", 3), ("adm", 4), ("tty", 5), ("disk", 6),
    ("lp", 7), ("mail", 8), ("news", 9), ("uucp", 10), ("man", 12), ("proxy", 13),
    ("kmem", 15), ("dialout", 20), ("fax", 21), ("voice", 22), ("cdrom", 24), ("floppy", 25),
    ("tape", 26), ("sudo", 27), ("audio", 29), ("dip", 30), ("www-data", 33), ("backup", 34),
    ("operator", 37), ("list", 38), ("irc", 39), ("src", 40), ("gnats", 41), ("shadow", 42),
    ("utmp", 43), ("video", 44), ("sasl", 45), ("plugdev", 46), ("staff", 50), ("games", 60),
    ("users", 100), ("nogroup", 65534), ("systemd-journal", 101), ("systemd-network", 102),
    ("systemd-resolve", 103), ("messagebus", 104), ("systemd-timesync", 105), ("input", 106),
    ("sgx", 107), ("kvm", 108), ("render", 109), ("lxd", 110), ("_ssh", 111), ("crontab", 112),
    ("syslog", 113), ("uuidd", 114), ("tcpdump", 115), ("tss", 116), ("landscape", 117),
]

_SBIN = {
    "arp", "blkid", "chpasswd", "chroot", "dmidecode", "ethtool", "fdisk", "groupadd", "halt",
    "ifconfig", "ip6tables", "iptables", "iptables-save", "modinfo", "nginx", "poweroff", "pwck",
    "reboot", "route", "runlevel", "service", "shutdown", "sysctl", "ufw", "useradd", "userdel",
    "usermod", "sshd", "cron", "rsyslogd", "lsmod",
}
_NOT_FILES = {"alias", "cd", "export", "hash", "history", "type", "umask", "unalias", "unset",
              "test", "time", "tilde", "true", "false"}
_SUID = [
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/fusermount3",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/libexec/polkit-agent-helper-1",
]
_BASE_DIRS = [
    "/boot", "/dev", "/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/default",
    "/etc/init.d", "/etc/network", "/etc/ssh", "/etc/ssl", "/etc/ssl/certs", "/etc/ssl/private",
    "/etc/sudoers.d", "/etc/systemd", "/etc/systemd/system", "/etc/apt", "/etc/skel", "/home",
    "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/srv", "/sys", "/tmp", "/usr",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib/openssh", "/usr/lib/dbus-1.0", "/usr/libexec",
    "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/share", "/var", "/var/backups",
    "/var/cache", "/var/lib", "/var/lib/apt", "/var/lib/dpkg", "/var/local", "/var/log",
    "/var/log/apt", "/var/mail", "/var/opt", "/var/spool", "/var/spool/cron",
    "/var/spool/cron/crontabs", "/var/tmp", "/lost+found", "/snap",
]
_LINKS = {"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib", "/lib64": "usr/lib64"}


def _h(seed: str, mod: int) -> int:
    return int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) % mod


def system_facts(host: VirtualHost) -> dict[str, Any]:
    facts = dict(DEFAULT_SYSTEM)
    facts.update(host.raw.get("system") or {})
    if "mac" not in (host.raw.get("system") or {}):
        facts["mac"] = "bc:24:11:" + ":".join(
            f"{_h(host.hostname + str(i), 256):02x}" for i in range(3)
        )
    return facts


def login_users(host: VirtualHost) -> list[dict[str, Any]]:
    """Human accounts from the YAML (uid >= 1000), with defaults filled in."""
    out = []
    for u in host.users:
        uid = int(u.get("uid", 1000))
        if uid < 1000:
            continue
        name = str(u["name"])
        out.append({
            "name": name,
            "uid": uid,
            "gid": int(u.get("gid", uid)),
            "gecos": str(u.get("gecos", f"{name},,,")),
            "home": str(u.get("home", f"/home/{name}")),
            "shell": str(u.get("shell", "/bin/bash")),
            "groups": list(u.get("groups") or []),
            "password": u.get("password"),
            "history": list(u.get("history") or []),
            "created": str(u.get("created", "")),
        })
    return out


def _service_users(host: VirtualHost) -> list[tuple[str, int, int, str, str, str]]:
    """Accounts like postgres that the YAML lists with uid < 1000."""
    known = {u[0] for u in _SYSTEM_USERS}
    out = []
    for u in host.users:
        uid = int(u.get("uid", 1000))
        name = str(u["name"])
        if uid >= 1000 or name in known:
            continue
        out.append((name, uid, int(u.get("gid", uid)), str(u.get("gecos", "")),
                    str(u.get("home", "/nonexistent")), str(u.get("shell", "/bin/bash"))))
    return out


def all_users(host: VirtualHost) -> list[tuple[str, int, int, str, str, str]]:
    rows = list(_SYSTEM_USERS) + _service_users(host)
    for u in login_users(host):
        rows.append((u["name"], u["uid"], u["gid"], u["gecos"], u["home"], u["shell"]))
    return rows


def _passwd(host: VirtualHost) -> str:
    return "".join(f"{n}:x:{uid}:{gid}:{g}:{home}:{sh}\n" for n, uid, gid, g, home, sh in all_users(host))


def _group(host: VirtualHost) -> str:
    members: dict[str, list[str]] = {}
    for u in login_users(host):
        for g in u["groups"]:
            members.setdefault(g, []).append(u["name"])
    lines = [f"{g}:x:{gid}:{','.join(members.get(g, []))}" for g, gid in _SYSTEM_GROUPS]
    have = {g for g, _ in _SYSTEM_GROUPS}
    for n, uid, gid, *_ in _service_users(host) + [
        (u["name"], u["uid"], u["gid"]) for u in login_users(host)
    ]:
        if n not in have:
            lines.append(f"{n}:x:{gid}:")
            have.add(n)
    return "\n".join(lines) + "\n"


def _fake_hash(seed: str) -> str:
    """Well-formed yescrypt-looking hash that matches no password."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    digest = hashlib.sha512(seed.encode()).digest()
    chars = "".join(alphabet[b % 64] for b in digest)
    return f"$y$j9T${chars[:22]}${chars[22:65]}"


def _shadow(host: VirtualHost, facts: dict) -> str:
    install_days = (clock.parse(facts["install_date"]) - clock.parse("1970-01-01")).days
    human = {u["name"] for u in login_users(host)} | {"root"}
    lines = []
    for n, *_ in all_users(host):
        if n in human:
            pw = _fake_hash(host.hostname + n)
            lines.append(f"{n}:{pw}:{install_days + _h(n, 300)}:0:99999:7:::")
        else:
            lines.append(f"{n}:*:{install_days}:0:99999:7:::")
    return "\n".join(lines) + "\n"


def _auth_log(host: VirtualHost, facts: dict) -> str:
    """Old admin logins + sudo + background brute force noise."""
    lines = []
    users = login_users(host)
    admin = users[0]["name"] if users else "root"
    ips = list(facts.get("admin_ips") or []) or [host.gateway]
    t0 = clock.now() - timedelta(days=6)
    noise = ["45.148.10.172", "218.92.0.112", "61.177.172.140", "193.32.162.38"]
    for day in range(6):
        base = t0 + timedelta(days=day, hours=8)
        ip = ips[day % len(ips)]
        port = 50000 + _h(f"{host.hostname}{day}", 15000)
        pid = 20000 + _h(f"pid{day}", 9000)
        ts = (base + clock.jitter(f"a{day}", 300)).strftime("%b %e %H:%M:%S")
        lines.append(f"{ts} {host.hostname} sshd[{pid}]: Accepted password for {admin} from {ip} port {port} ssh2")
        lines.append(f"{ts} {host.hostname} sshd[{pid}]: pam_unix(sshd:session): session opened for user {admin}(uid=1000) by (uid=0)")
        if day % 2 == 0:
            ts2 = (base + clock.jitter(f"s{day}", 300) + timedelta(minutes=5)).strftime("%b %e %H:%M:%S")
            lines.append(f"{ts2} {host.hostname} sudo:    {admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/bin/systemctl restart {(host.services or [{'name': 'ssh'}])[0].get('name', 'ssh')}")
        bad = noise[day % len(noise)]
        ts3 = (base + timedelta(hours=10) + clock.jitter(f"n{day}", 200)).strftime("%b %e %H:%M:%S")
        lines.append(f"{ts3} {host.hostname} sshd[{pid + 77}]: Invalid user oracle from {bad} port {port + 3}")
        lines.append(f"{ts3} {host.hostname} sshd[{pid + 77}]: Failed password for invalid user oracle from {bad} port {port + 3} ssh2")
        lines.append(f"{ts3} {host.hostname} sshd[{pid + 78}]: Failed password for root from {bad} port {port + 9} ssh2")
    return "\n".join(lines) + "\n"


def _syslog(host: VirtualHost) -> str:
    t = clock.now() - timedelta(hours=2)
    ts = lambda m: (t + timedelta(minutes=m)).strftime("%b %e %H:%M:%S")  # noqa: E731
    h = host.hostname
    return (
        f"{ts(0)} {h} systemd[1]: Starting Daily apt download activities...\n"
        f"{ts(1)} {h} systemd[1]: apt-daily.service: Deactivated successfully.\n"
        f"{ts(1)} {h} systemd[1]: Finished Daily apt download activities.\n"
        f"{ts(17)} {h} CRON[{31000 + _h(h, 900)}]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)\n"
        f"{ts(45)} {h} systemd-timesyncd[612]: Network configuration changed, trying to establish connection.\n"
        f"{ts(45)} {h} systemd-timesyncd[612]: Initial synchronization to time server 185.125.190.56:123 (ntp.ubuntu.com).\n"
        f"{ts(77)} {h} CRON[{31200 + _h(h, 900)}]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)\n"
    )


def _dpkg_log(host: VirtualHost, facts: dict) -> str:
    when = clock.parse(facts["install_date"]) + timedelta(hours=2)
    pkgs = ["openssh-server:amd64 1:8.9p1-3ubuntu0.10", "curl:amd64 7.81.0-1ubuntu1.16",
            "net-tools:amd64 1.60+git20181103.0eebece-1ubuntu5", "nmap:amd64 7.80+dfsg1-2build1"]
    for s in host.services:
        name = s.get("name")
        if name == "nginx":
            pkgs.append("nginx:amd64 1.18.0-6ubuntu14.4")
        if name == "postgresql":
            pkgs.append("postgresql-14:amd64 14.11-0ubuntu0.22.04.1")
    lines = []
    for i, p in enumerate(pkgs):
        ts = clock.stamp(when + timedelta(minutes=3 * i))
        lines.append(f"{ts} install {p.split(' ')[0]} <none> {p.split(' ')[1]}")
        lines.append(f"{ts} status installed {p.split(' ')[0]} {p.split(' ')[1]}")
    return "\n".join(lines) + "\n"


def _etc_files(host: VirtualHost, facts: dict) -> dict[str, str]:
    h = host.hostname
    users = login_users(host)
    fqdn = host.fqdn or f"{h}.corp.local"
    files = {
        "/etc/hostname": f"{h}\n",
        "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {fqdn} {h}\n{host.ip} {fqdn} {h}\n\n"
                      "# The following lines are desirable for IPv6 capable hosts\n"
                      "::1     ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n",
        "/etc/os-release": (
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
            'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
            "UBUNTU_CODENAME=jammy\n"
        ),
        "/etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n"
                            'DISTRIB_DESCRIPTION="Ubuntu 22.04.4 LTS"\n',
        "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n\n",
        "/etc/issue.net": "Ubuntu 22.04.4 LTS\n",
        "/etc/debian_version": "bookworm/sid\n",
        "/etc/timezone": "Etc/UTC\n",
        "/etc/machine-id": hashlib.md5(h.encode()).hexdigest() + "\n",
        "/etc/environment": 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"\n',
        "/etc/shells": "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/usr/bin/sh\n/bin/dash\n/usr/bin/dash\n/usr/bin/tmux\n/usr/bin/screen\n",
        "/etc/resolv.conf": "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n"
                            "# Do not edit.\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch corp.local\n",
        "/etc/fstab": "# /etc/fstab: static file system information.\n"
                      f"/dev/disk/by-uuid/{hashlib.md5((h + 'r').encode()).hexdigest()[:8]}-4c1e-4b6a-9d2e-{hashlib.md5(h.encode()).hexdigest()[:12]} / ext4 defaults 0 1\n"
                      "/dev/disk/by-uuid/5B1C-2F0A /boot/efi vfat defaults 0 1\n/swap.img\tnone\tswap\tsw\t0\t0\n",
        "/etc/crontab": "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\n"
                        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                        "# m h dom mon dow user\tcommand\n"
                        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
                        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                        "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
                        "52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n#\n",
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n\n#Port 22\n#PermitRootLogin prohibit-password\n"
                                "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\n"
                                "X11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\n"
                                "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n",
        "/etc/ssh/ssh_host_ed25519_key.pub": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{hashlib.sha256((h + 'ed').encode()).hexdigest()[:43]} root@{h}\n",
        "/etc/sudoers": "Defaults\tenv_reset\nDefaults\tmail_badpass\n"
                        'Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"\n'
                        "Defaults\tuse_pty\n\nroot\tALL=(ALL:ALL) ALL\n\n%admin ALL=(ALL) ALL\n\n%sudo\tALL=(ALL:ALL) ALL\n\n"
                        "@includedir /etc/sudoers.d\n",
        "/etc/passwd": _passwd(host),
        "/etc/group": _group(host),
        "/etc/shadow": _shadow(host, facts),
        "/proc/version": f"Linux version {facts['kernel']} (buildd@lcy02-amd64-051) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "
                         f"GNU ld (GNU Binutils for Ubuntu) 2.38) {facts['kernel_build']}\n",
        "/proc/cpuinfo": "".join(
            f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 44\n"
            f"model name\t: {facts['cpu_model']}\nstepping\t: 2\ncpu MHz\t\t: 2666.760\n"
            f"cache size\t: 12288 KB\ncpu cores\t: {facts['cpus']}\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc pni ssse3 cx16 sse4_1 sse4_2 popcnt aes hypervisor lahf_lm\n\n"
            for i in range(int(facts["cpus"]))
        ),
        "/var/log/auth.log": _auth_log(host, facts),
        "/var/log/syslog": _syslog(host),
        "/var/log/dpkg.log": _dpkg_log(host, facts),
        "/var/log/apt/history.log": f"\nStart-Date: {clock.stamp(clock.parse(facts['install_date']) + timedelta(hours=2))}\n"
                                    "Commandline: apt install -y curl net-tools nmap\n"
                                    "Install: nmap:amd64 (7.80+dfsg1-2build1), net-tools:amd64 (1.60+git20181103.0eebece-1ubuntu5)\n"
                                    f"End-Date: {clock.stamp(clock.parse(facts['install_date']) + timedelta(hours=2, minutes=1))}\n",
        "/etc/skel/.bashrc": _BASHRC,
        "/etc/skel/.profile": _PROFILE,
    }
    if any(u["groups"] for u in users):
        pass
    return files


_BASHRC = (
    "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
    "case $- in\n    *i*) ;;\n      *) return;;\nesac\n\n"
    "HISTCONTROL=ignoreboth\nshopt -s histappend\nHISTSIZE=1000\nHISTFILESIZE=2000\n"
    "shopt -s checkwinsize\n\n"
    "if [ -x /usr/bin/dircolors ]; then\n    alias ls='ls --color=auto'\n    alias grep='grep --color=auto'\nfi\n\n"
    "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n\n"
    "if [ -f ~/.bash_aliases ]; then\n    . ~/.bash_aliases\nfi\n"
)
_PROFILE = (
    "# ~/.profile: executed by the command interpreter for login shells.\n"
    'if [ -n "$BASH_VERSION" ]; then\n    if [ -f "$HOME/.bashrc" ]; then\n\t. "$HOME/.bashrc"\n    fi\nfi\n\n'
    'if [ -d "$HOME/bin" ] ; then\n    PATH="$HOME/bin:$PATH"\nfi\n'
)
_BASH_LOGOUT = (
    "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n"
    'if [ "$SHLVL" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n'
)


def _put(fs: dict, path: str, meta: dict) -> None:
    """Add an entry unless the YAML already defines it; fill missing metadata."""
    if path in fs:
        for k, v in meta.items():
            fs[path].setdefault(k, v)
        return
    fs[path] = meta


def apply_system_pack(host: VirtualHost) -> None:
    """Merge the generated Ubuntu system into host.filesystem (YAML wins)."""
    if host.raw.get("system_pack") is False:
        return
    facts = system_facts(host)
    host.system = facts
    fs = host.filesystem
    install = clock.parse(facts["install_date"])

    for d in _BASE_DIRS:
        _put(fs, d, {"type": "dir"})
    for link, target in _LINKS.items():
        _put(fs, link, {"type": "link", "target": target, "mode": "0777"})
    fs["/"] = {**fs.get("/", {}), "type": "dir"}

    for path, content in _etc_files(host, facts).items():
        _put(fs, path, {"type": "file", "content": content})

    for name in KNOWN_BINARIES - _NOT_FILES:
        base = "/usr/sbin" if name in _SBIN else "/usr/bin"
        _put(fs, f"{base}/{name}", {"type": "file", "binary": True, "mode": "0755",
                                     "size": 18000 + _h(name, 900000)})
    for path in _SUID:
        _put(fs, path, {"type": "file", "binary": True, "mode": "4755",
                        "size": 30000 + _h(path, 200000)})

    for u in login_users(host):
        home = u["home"]
        created = clock.parse(u["created"]) if u["created"] else install + timedelta(days=3)
        _put(fs, home, {"type": "dir", "owner": u["name"], "group": u["name"], "mode": "0750",
                        "mtime": clock.stamp(created)})
        for dot, content in ((".bashrc", _BASHRC), (".profile", _PROFILE), (".bash_logout", _BASH_LOGOUT)):
            _put(fs, f"{home}/{dot}", {"type": "file", "content": content, "owner": u["name"],
                                        "group": u["name"], "mtime": clock.stamp(created)})
        hist = "\n".join(u["history"]) + ("\n" if u["history"] else "")
        _put(fs, f"{home}/.bash_history", {"type": "file", "content": hist, "owner": u["name"],
                                            "group": u["name"], "mode": "0600",
                                            "mtime": clock.stamp(clock.now() - timedelta(days=2, hours=5))})
        _put(fs, f"{home}/.cache", {"type": "dir", "owner": u["name"], "group": u["name"], "mode": "0700"})
        _put(fs, f"{home}/.ssh", {"type": "dir", "owner": u["name"], "group": u["name"], "mode": "0700"})
    _put(fs, "/root/.bashrc", {"type": "file", "content": _BASHRC})
    _put(fs, "/root/.profile", {"type": "file", "content": _PROFILE})
    _put(fs, "/root/.bash_history", {"type": "file", "mode": "0600", "content":
         "apt update\napt upgrade -y\nsystemctl status ssh\nufw status\nreboot\n"})
    _put(fs, "/root/.ssh", {"type": "dir", "mode": "0700"})

    _fill_metadata(host, facts)
    host.processes = build_processes(host, facts)


def _owner_for(host: VirtualHost, path: str) -> tuple[str, str]:
    for u in login_users(host):
        if path == u["home"] or path.startswith(u["home"] + "/"):
            return u["name"], u["name"]
    for n, _uid, _gid, _g, home, _sh in _service_users(host):
        if home not in {"/nonexistent", "/"} and (path == home or path.startswith(home + "/")):
            return n, n
    if path in {"/var/log/auth.log", "/var/log/syslog"}:
        return "syslog", "adm"
    if path == "/etc/shadow":
        return "root", "shadow"
    if path == "/var/log":
        return "root", "syslog"
    if path == "/var/spool/cron/crontabs":
        return "root", "crontab"
    return "root", "root"


def _mode_for(path: str, meta: dict) -> str:
    if meta.get("type") == "dir":
        if path in {"/tmp", "/var/tmp"}:
            return "1777"
        if path in {"/root", "/lost+found", "/etc/ssl/private"} or path.endswith("/.ssh"):
            return "0700"
        if path == "/var/spool/cron/crontabs":
            return "1730"
        if path in {"/proc", "/sys"}:
            return "0555"
        if path == "/var/log":
            return "0775"
        return "0755"
    name = path.rsplit("/", 1)[-1]
    if path == "/etc/shadow":
        return "0640"
    if path in {"/etc/sudoers"}:
        return "0440"
    if path in {"/var/log/auth.log", "/var/log/syslog"}:
        return "0640"
    if name.startswith("id_") and not name.endswith(".pub"):
        return "0600"
    if name in {".bash_history", "credentials", ".pgpass", ".env"}:
        return "0600"
    if path.startswith("/root/"):
        return "0600" if name.startswith(".") else "0644"
    return "0644"


def _mtime_for(host: VirtualHost, path: str, meta: dict, facts: dict) -> str:
    install = clock.parse(facts["install_date"])
    if path.startswith("/var/log/") or path.startswith("/proc") or path in {"/tmp", "/var/tmp", "/run", "/dev"}:
        return clock.stamp(clock.now() - clock.jitter(path, 90))
    if path.startswith("/usr/") or path in _LINKS or path in _BASE_DIRS:
        return clock.stamp(install + clock.jitter(path, 120))
    if path.startswith("/etc/"):
        return clock.stamp(install + clock.jitter(path, 60 * 24 * 200))
    # user / app data: somewhere between install and a month ago
    span = max((clock.now() - install).days - 30, 1)
    return clock.stamp(install + timedelta(days=_h(path, span)) + clock.jitter(path, 600))


def _fill_metadata(host: VirtualHost, facts: dict) -> None:
    for path, meta in host.filesystem.items():
        owner, group = _owner_for(host, path)
        meta.setdefault("owner", owner)
        meta.setdefault("group", meta.get("owner", group) if meta.get("owner") not in (None, "root") else group)
        meta.setdefault("mode", _mode_for(path, meta))
        meta.setdefault("mtime", _mtime_for(host, path, meta, facts))


def build_processes(host: VirtualHost, facts: dict) -> list[dict[str, Any]]:
    """ps aux table: kernel + systemd basics + one block per service + YAML extras."""
    boot = clock.boot_time(facts)
    start = boot.strftime("%b%d") if (clock.now() - boot).days else boot.strftime("%H:%M")
    rows: list[dict[str, Any]] = []

    def add(user: str, pid: int, cmd: str, vsz: int, rss: int, stat: str = "Ss",
            cpu: float = 0.0, tty: str = "?", started: str = start, time: str = "0:00") -> None:
        mem = round(rss / (facts["memory_mb"] * 1024) * 100, 1)
        rows.append({"user": user, "pid": pid, "cmd": cmd, "vsz": vsz, "rss": rss, "stat": stat,
                     "cpu": cpu, "mem": mem, "tty": tty, "start": started, "time": time})

    add("root", 1, "/sbin/init", 167500, 12900, time="1:42")
    add("root", 2, "[kthreadd]", 0, 0, "S")
    add("root", 3, "[rcu_gp]", 0, 0, "I<")
    add("root", 4, "[rcu_par_gp]", 0, 0, "I<")
    add("root", 11, "[ksoftirqd/0]", 0, 0, "S", time="0:09")
    add("root", 12, "[rcu_sched]", 0, 0, "I", time="2:11")
    add("root", 362, "/lib/systemd/systemd-journald", 64220, 21800, "S<s", time="0:31")
    add("root", 401, "/lib/systemd/systemd-udevd", 25800, 6400, "Ss")
    add("systemd+", 588, "/lib/systemd/systemd-networkd", 16400, 8100, "Ss")
    add("systemd+", 590, "/lib/systemd/systemd-resolved", 25500, 12900, "Ss")
    add("systemd+", 612, "/lib/systemd/systemd-timesyncd", 89300, 6600, "Ssl")
    add("root", 655, "/usr/sbin/cron -f -P", 6900, 2800, "Ss")
    add("message+", 656, "@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only", 8600, 4900, "Ss")
    add("syslog", 662, "/usr/sbin/rsyslogd -n -iNONE", 222400, 5900, "Ssl")
    add("root", 665, "/lib/systemd/systemd-logind", 15200, 7300, "Ss")
    add("root", 690, "/sbin/agetty -o -p -- \\u --noclear tty1 linux", 6200, 1100, "Ss+", tty="tty1")
    add("root", 712, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", 15400, 9100, "Ss")

    pid = 880
    for svc in host.services:
        name = str(svc.get("name"))
        if name == "nginx":
            add("root", pid, "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", 55300, 1600)
            add("www-data", pid + 1, "nginx: worker process", 56000, 5300, "S")
            add("www-data", pid + 2, "nginx: worker process", 56000, 5300, "S")
        elif name == "postgresql":
            add("postgres", pid, "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf", 217000, 29400, "Ss", time="0:52")
            for i, role in enumerate(("checkpointer", "background writer", "walwriter", "autovacuum launcher", "logical replication launcher")):
                add("postgres", pid + 1 + i, f"postgres: 14/main: {role} ", 217100, 6000 + 900 * i, "Ss")
        elif name == "redis":
            add("redis", pid, "/usr/bin/redis-server 127.0.0.1:6379", 67800, 9800, "Ssl", time="3:05")
        elif name not in {"ssh"}:
            cmd = str(svc.get("cmd") or f"/usr/local/bin/{name}")
            add(str(svc.get("user", "root")), pid, cmd, 120000, 34000, "Ssl")
        pid += 40
    for p in host.raw.get("processes") or []:
        cmd = str(p.get("cmd", ""))
        if any(cmd == r["cmd"] for r in rows) or cmd in {"/sbin/init", "/usr/sbin/sshd -D", "-bash"} or cmd.startswith("nginx:"):
            continue
        add(str(p.get("user", "root")), int(p.get("pid", pid)), cmd, int(p.get("vsz", 90000)),
            int(p.get("rss", 12000)), str(p.get("stat", "Ssl")))
        pid += 7
    return rows


def listening_sockets(host: VirtualHost) -> list[dict[str, Any]]:
    """Sockets for ss/netstat — derived from services, so nmap/ss/ps agree."""
    procs = {r["cmd"].split()[0]: r["pid"] for r in host.processes}
    sshd = next((r["pid"] for r in host.processes if r["cmd"].startswith("sshd:")), 712)
    socks = [
        {"proto": "udp", "local": "127.0.0.53%lo:53", "proc": "systemd-resolve", "pid": 590},
        {"proto": "tcp", "local": "127.0.0.53%lo:53", "proc": "systemd-resolve", "pid": 590},
        {"proto": "tcp", "local": "0.0.0.0:22", "proc": "sshd", "pid": sshd},
        {"proto": "tcp6", "local": "[::]:22", "proc": "sshd", "pid": sshd},
    ]
    for svc in host.services:
        name = str(svc.get("name"))
        port = svc.get("port")
        if not port or name == "ssh":
            continue
        bind = str(svc.get("bind", "127.0.0.1" if name == "redis" else "0.0.0.0"))
        proc = {"postgresql": "postgres", "redis": "redis-server"}.get(name, name)
        pid = next((r["pid"] for r in host.processes if proc in r["cmd"].split("/")[-1] or r["cmd"].startswith(proc)), procs.get(name, 900))
        socks.append({"proto": "tcp", "local": f"{bind}:{port}", "proc": proc, "pid": pid})
    return socks
