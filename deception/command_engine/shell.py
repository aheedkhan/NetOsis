"""Bash-like line handling: `;` `&&` `||`, pipes, redirects, $VAR expansion,
and text filters (grep/head/tail/wc/sort/uniq/cut/awk/...) for pipelines.

Attackers chain almost everything (`cat /etc/passwd | grep bash`,
`ps aux | grep root`, `find / -perm -4000 2>/dev/null`), so this layer is what
keeps those answers deterministic instead of falling through to the LLM.
"""

from __future__ import annotations

import base64
import fnmatch
import re
import shlex
from dataclasses import dataclass


def _scan(line: str, seps: tuple[str, ...]) -> list[tuple[str, str]]:
    """Split on separators outside quotes. Returns [(sep_before, part), ...]."""
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    quote = ""
    prev_sep = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"' and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 1
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < len(line):
            buf.append(ch + line[i + 1])
            i += 2
            continue
        matched = next((s for s in seps if line.startswith(s, i)), None)
        if matched:
            out.append((prev_sep, "".join(buf).strip()))
            buf = []
            prev_sep = matched
            i += len(matched)
            continue
        buf.append(ch)
        i += 1
    out.append((prev_sep, "".join(buf).strip()))
    return out


def split_chain(line: str) -> list[tuple[str, str]]:
    parts = _scan(line, ("&&", "||", ";"))
    return [(sep, seg) for sep, seg in parts if seg]


def split_pipe(segment: str) -> list[str]:
    # `||` was consumed by split_chain, so a lone `|` here is a pipe.
    return [p for _sep, p in _scan(segment, ("|",)) if p]


@dataclass
class Redirects:
    stdout_file: str | None = None
    append: bool = False
    stdout_null: bool = False
    stderr_null: bool = False
    stderr_merge: bool = False
    stdin_file: str | None = None


_REDIR_RE = re.compile(r"(\d?&?>>?|<)\s*(&1|\S+)")


def strip_redirects(stage: str) -> tuple[str, Redirects]:
    r = Redirects()
    out: list[str] = []
    for sep, part in _scan(stage, (">>", "2>&1", "&>", "2>", ">", "<")):
        if not sep:
            out.append(part)
            continue
        target, _, rest = part.partition(" ")
        if sep == "2>&1":
            r.stderr_merge = True
            out.append(part)
            continue
        if sep in {"2>"}:
            if target in {"/dev/null"}:
                r.stderr_null = True
            out.append(rest)
            continue
        if sep == "&>":
            r.stdout_null = r.stderr_null = target == "/dev/null"
            if target != "/dev/null":
                r.stdout_file = target
            out.append(rest)
            continue
        if sep == "<":
            r.stdin_file = target
            out.append(rest)
            continue
        if target == "/dev/null":
            r.stdout_null = True
        else:
            r.stdout_file = target
            r.append = sep == ">>"
        out.append(rest)
    return " ".join(p for p in out if p).strip(), r


def expand_vars(stage: str, env: dict[str, str]) -> str:
    """$VAR / ${VAR} / leading ~ — skipped inside single quotes."""
    out: list[str] = []
    for i, chunk in enumerate(re.split(r"('[^']*')", stage)):
        if i % 2 == 1:
            out.append(chunk)
            continue
        chunk = re.sub(r"(^|\s)~(?=/|\s|$)", lambda m: m.group(1) + env.get("HOME", "/"), chunk)
        chunk = re.sub(r"\$\{(\w+)\}|\$(\w+|\?)", lambda m: env.get(m.group(1) or m.group(2), ""), chunk)
        out.append(chunk)
    return "".join(out)


def argv(stage: str) -> list[str]:
    try:
        return shlex.split(stage)
    except ValueError:
        return stage.split()


# --------------------------------------------------------------------------- filters

FILTERS = {"grep", "egrep", "fgrep", "head", "tail", "wc", "sort", "uniq", "cut", "awk",
           "tr", "base64", "tee", "cat", "less", "more", "column", "nl", "rev", "tac", "sed", "xargs"}


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _join(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


def _num_arg(args: list[str], default: int) -> int:
    for i, a in enumerate(args):
        if a == "-n" and i + 1 < len(args):
            try:
                return int(args[i + 1].lstrip("+"))
            except ValueError:
                return default
        if re.fullmatch(r"-n?\d+", a):
            return int(a.lstrip("-n"))
        if a.startswith("--lines="):
            return int(a.split("=", 1)[1])
    return default


def grep_lines(args: list[str], lines: list[str]) -> tuple[list[str], bool]:
    """Return (matching lines, pattern_given) honouring -i -v -E -w -c -n -o."""
    flags = set()
    patterns: list[str] = []
    rest: list[str] = []
    it = iter(range(len(args)))
    skip = False
    for i in it:
        if skip:
            skip = False
            continue
        a = args[i]
        if a == "-e" and i + 1 < len(args):
            patterns.append(args[i + 1])
            skip = True
        elif a.startswith("--"):
            flags.add(a)
        elif a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            rest.append(a)
    if not patterns and rest:
        patterns.append(rest.pop(0))
    if not patterns:
        return [], False
    re_flags = re.I if "i" in flags else 0
    regs = []
    for p in patterns:
        expr = p if ("E" in flags or "P" in flags) else _basic_to_ere(p)
        if "F" in flags:
            expr = re.escape(p)
        if "w" in flags:
            expr = rf"\b(?:{expr})\b"
        try:
            regs.append(re.compile(expr, re_flags))
        except re.error:
            regs.append(re.compile(re.escape(p), re_flags))
    out = []
    for n, ln in enumerate(lines, 1):
        hit = any(r.search(ln) for r in regs)
        if hit != ("v" in flags):
            if "o" in flags and "v" not in flags:
                out.extend(m.group(0) for r in regs for m in r.finditer(ln))
            else:
                out.append(f"{n}:{ln}" if "n" in flags else ln)
    if "c" in flags:
        return [str(len(out))], True
    return out, True


def _basic_to_ere(p: str) -> str:
    # BRE: \| \( \) are operators, bare | ( ) + ? are literal.
    p = re.sub(r"(?<!\\)([|()+?{}])", r"\\\1", p)
    return p.replace(r"\\|", "|").replace(r"\\(", "(").replace(r"\\)", ")")


def apply_filter(name: str, args: list[str], text: str) -> tuple[str, str, int] | None:
    """Run a text filter on stdin text. Returns (stdout, stderr, exit) or None."""
    lines = _lines(text)
    if name in {"grep", "egrep", "fgrep"}:
        if name == "egrep":
            args = ["-E", *args]
        if name == "fgrep":
            args = ["-F", *args]
        out, ok = grep_lines(args, lines)
        if not ok:
            return "", "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
        return _join(out), "", 0 if out and out != ["0"] else 1
    if name == "head":
        if any(a.startswith("-c") for a in args):
            n = int(re.sub(r"\D", "", "".join(args)) or 10)
            return text[:n], "", 0
        return _join(lines[: _num_arg(args, 10)]), "", 0
    if name == "tail":
        n = _num_arg(args, 10)
        if any(a.startswith("-n+") or a == "+%d" % n for a in args) or ("-n" in args and args[args.index("-n") + 1].startswith("+")):
            return _join(lines[n - 1:]), "", 0
        return _join(lines[-n:] if n else []), "", 0
    if name == "wc":
        nl = text.count("\n")
        words = len(text.split())
        chars = len(text.encode())
        if "-l" in args:
            return f"{nl}\n", "", 0
        if "-w" in args:
            return f"{words}\n", "", 0
        if "-c" in args or "-m" in args:
            return f"{chars}\n", "", 0
        return f"{nl:7d} {words:7d} {chars:7d}\n", "", 0
    if name == "sort":
        key = None
        if "-n" in args or any(a.startswith("-") and "n" in a[1:] and not a.startswith("--") for a in args):
            def key(s: str) -> float:  # noqa: E306
                m = re.match(r"\s*(-?\d+(?:\.\d+)?)", s)
                return float(m.group(1)) if m else 0.0
        out = sorted(lines, key=key) if key else sorted(lines)
        if any(a in {"-r", "-rn", "-nr"} for a in args):
            out.reverse()
        if "-u" in args:
            out = list(dict.fromkeys(out))
        return _join(out), "", 0
    if name == "uniq":
        out: list[str] = []
        counts: list[int] = []
        for ln in lines:
            if out and out[-1] == ln:
                counts[-1] += 1
            else:
                out.append(ln)
                counts.append(1)
        if "-c" in args:
            return _join([f"{c:7d} {ln}" for c, ln in zip(counts, out)]), "", 0
        return _join(out), "", 0
    if name == "cut":
        delim = "\t"
        fields: list[int] = []
        chars: tuple[int, int] | None = None
        for i, a in enumerate(args):
            if a.startswith("-d"):
                delim = a[2:] if len(a) > 2 else (args[i + 1] if i + 1 < len(args) else "\t")
            if a.startswith("-f"):
                spec = a[2:] if len(a) > 2 else (args[i + 1] if i + 1 < len(args) else "1")
                fields = _ranges(spec)
            if a.startswith("-c"):
                spec = a[2:] if len(a) > 2 else (args[i + 1] if i + 1 < len(args) else "1")
                r = _ranges(spec)
                chars = (min(r), max(r)) if r else None
        out = []
        for ln in lines:
            if chars:
                out.append(ln[chars[0] - 1: chars[1]])
            elif fields:
                parts = ln.split(delim)
                if len(parts) == 1:
                    out.append(ln)
                else:
                    out.append(delim.join(parts[f - 1] for f in fields if f - 1 < len(parts)))
        return _join(out), "", 0
    if name == "awk":
        return _awk(args, lines)
    if name == "tr":
        sets = [a for a in args if not a.startswith("-")]
        if "-d" in args and sets:
            return "".join(c for c in text if c not in _tr_set(sets[0])), "", 0
        if len(sets) >= 2:
            src, dst = _tr_set(sets[0]), _tr_set(sets[1])
            if dst:
                dst = dst + dst[-1] * max(0, len(src) - len(dst))
                return text.translate(str.maketrans(src, dst[: len(src)])), "", 0
        return text, "", 0
    if name == "base64":
        if "-d" in args or "--decode" in args:
            try:
                return base64.b64decode(text.strip() + "===").decode(errors="replace"), "", 0
            except Exception:
                return "", "base64: invalid input\n", 1
        enc = base64.b64encode(text.encode()).decode()
        return _join([enc[i:i + 76] for i in range(0, len(enc), 76)]), "", 0
    if name in {"cat", "less", "more", "column", "tee"}:
        return text, "", 0
    if name == "nl":
        return _join([f"{i:6d}\t{ln}" for i, ln in enumerate(lines, 1)]), "", 0
    if name == "rev":
        return _join([ln[::-1] for ln in lines]), "", 0
    if name == "tac":
        return _join(lines[::-1]), "", 0
    if name == "sed":
        return _sed(args, lines)
    return None


def _ranges(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            out.extend(range(int(a or 1), int(b or 50) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def _tr_set(s: str) -> str:
    s = s.replace("[:upper:]", "A-Z").replace("[:lower:]", "a-z").replace("[:digit:]", "0-9")
    s = s.replace("\\n", "\n").replace("\\t", "\t")
    out = []
    i = 0
    while i < len(s):
        if i + 2 < len(s) and s[i + 1] == "-":
            out.extend(chr(c) for c in range(ord(s[i]), ord(s[i + 2]) + 1))
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _awk(args: list[str], lines: list[str]) -> tuple[str, str, int]:
    """awk subset: -F sep, optional /regex/, print $N[, $M] / print $NF / print."""
    sep = None
    prog = ""
    for i, a in enumerate(args):
        if a.startswith("-F"):
            sep = a[2:] or (args[i + 1] if i + 1 < len(args) else None)
        elif not a.startswith("-") and not prog and (i == 0 or not args[i - 1] == "-F"):
            prog = a
    if sep in {"\\t", "'\\t'"}:
        sep = "\t"
    m = re.match(r"\s*(?:/(.*?)/)?\s*(?:\$(\d+)\s*(==|~)\s*\"?([^\"]*)\"?)?\s*\{\s*print\s*(.*?)\s*;?\s*\}\s*$", prog)
    if not m:
        return _join(lines), "", 0
    regex, cond_field, cond_op, cond_val, fields = m.groups()
    out = []
    for ln in lines:
        parts = ln.split(sep) if sep else ln.split()
        if regex and not re.search(regex, ln):
            continue
        if cond_field:
            idx = int(cond_field)
            val = parts[idx - 1] if 0 < idx <= len(parts) else (ln if idx == 0 else "")
            if cond_op == "==" and val != cond_val:
                continue
            if cond_op == "~" and not re.search(cond_val.strip("/"), val):
                continue
        if not fields or fields.strip() == "$0":
            out.append(ln)
            continue
        vals = []
        for f in re.split(r"\s*,\s*|\s+", fields.strip()):
            if f == "$NF":
                vals.append(parts[-1] if parts else "")
            elif re.fullmatch(r"\$\d+", f):
                idx = int(f[1:])
                vals.append(ln if idx == 0 else (parts[idx - 1] if idx - 1 < len(parts) else ""))
            elif f.startswith('"') and f.endswith('"'):
                vals.append(f[1:-1])
        out.append(" ".join(vals))
    return _join(out), "", 0


def _sed(args: list[str], lines: list[str]) -> tuple[str, str, int]:
    exprs = [a for a in args if not a.startswith("-")]
    quiet = "-n" in args
    if not exprs:
        return _join(lines), "", 0
    e = exprs[0]
    m = re.fullmatch(r"(\d+)(?:,(\d+))?p", e)
    if m and quiet:
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        return _join(lines[a - 1: b]), "", 0
    m = re.fullmatch(r"s(.)(.*?)\1(.*?)\1(g?)", e)
    if m:
        _, pat, rep, g = m.groups()
        try:
            rx = re.compile(pat)
        except re.error:
            rx = re.compile(re.escape(pat))
        return _join([rx.sub(rep.replace("&", r"\g<0>"), ln, count=0 if g else 1) for ln in lines]), "", 0
    return _join(lines), "", 0


def glob_match(name: str, pattern: str, *, ignore_case: bool = False) -> bool:
    if ignore_case:
        return fnmatch.fnmatch(name.lower(), pattern.lower())
    return fnmatch.fnmatchcase(name, pattern)
