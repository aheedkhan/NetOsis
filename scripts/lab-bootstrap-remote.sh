#!/usr/bin/env bash
# Run ON the lab honeypot host after rsync (creates venv, installs deps, installs systemd unit).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Re-run as root (needed for useradd / systemd install)." >&2
  exit 1
fi

id -u netosis >/dev/null 2>&1 || useradd --system --home "$ROOT" --shell /usr/sbin/nologin netosis

python3 -m venv "$ROOT/.venv"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
pip install -U pip
pip install -r "$ROOT/requirements.txt"

mkdir -p "$ROOT/data"
chown -R netosis:netosis "$ROOT"

if [[ ! -f "$ROOT/.env" ]]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "[*] Created .env from example — edit NETOSIS_LLM_* and bind settings."
fi

# Ensure Qwen mode for lab CPU host (edit if Ollama elsewhere)
grep -q '^NETOSIS_LLM_MODE=' "$ROOT/.env" && \
  sed -i 's/^NETOSIS_LLM_MODE=.*/NETOSIS_LLM_MODE=qwen/' "$ROOT/.env" || \
  echo 'NETOSIS_LLM_MODE=qwen' >>"$ROOT/.env"

install -m 0644 "$ROOT/ops/systemd/netosis-ssh.service" /etc/systemd/system/netosis-ssh.service
systemctl daemon-reload
systemctl enable netosis-ssh.service
systemctl restart netosis-ssh.service
systemctl --no-pager --full status netosis-ssh.service || true

echo
echo "[+] netosis-ssh.service installed."
echo "    journalctl -u netosis-ssh -f"
echo "    Local test: ssh admin@127.0.0.1 -p 2222"
echo
echo "[!] Ollama must be reachable at NETOSIS_LLM_BASE_URL (default 127.0.0.1:11434)."
echo "    On this host: ollama pull qwen2.5:3b"
