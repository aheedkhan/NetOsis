"""Commands that exist on the fake Ubuntu host.

Anything else answers `command not found` instantly instead of waiting on the
LLM — real bash does the same, and it keeps junk input off the slow path.
"""

from __future__ import annotations

KNOWN_BINARIES = frozenset(
    """
    alias apropos arch arp awk base64 basename bash bc blkid bunzip2 bzip2 cal chage chattr
    chgrp chmod chown chpasswd chroot cksum clear cmp column comm cp crontab csplit cut
    date dd df diff dig dirname dmesg dmidecode dnsdomainname docker dpkg du egrep env
    ethtool expand export expr factor fallocate false fdisk fgrep file find findmnt fmt
    fold free fuser gawk getent gpasswd grep groupadd groups gunzip gzip halt hash head
    hexdump history host hostname hostnamectl htop iconv ifconfig install iostat ip6tables
    iptables iptables-save journalctl jq kill killall last lastb lastlog less ln locale
    localectl locate logger login loginctl logname lsattr lsb_release lsblk lscpu lshw
    lsmod lsof lspci lsusb man md5sum mknod mktemp modinfo more mount mpstat mv mysql
    nano nc ncat netcat netstat networkctl newgrp nginx nice nl nohup nproc nslookup
    numfmt od openssl passwd paste perl pgrep php pidof ping ping6 pinky pkill pmap
    poweroff pr printenv printf psql pstree pwck python python3 readlink realpath reboot
    redis-cli renice reset resolvectl route rsync runlevel scp screen sed seq service
    sftp sh sha1sum sha256sum sha512sum shred shuf shutdown sleep sort split ss ssh
    ssh-keygen stat strace strings stty sum sync sysctl systemctl tac tail tar tee telnet
    test tilde time timedatectl timeout tmux top tr traceroute true truncate tty type
    ufw umask umount unalias uname uniq unset unzip uptime useradd userdel usermod users
    vi vim vmstat w wall watch wc whatis whereis which who xargs xxd yes zcat zip
    """.split()
)


def is_plausible_command(name: str) -> bool:
    """True for real binaries and explicit paths (./x, /usr/bin/x)."""
    return "/" in name or name in KNOWN_BINARIES
