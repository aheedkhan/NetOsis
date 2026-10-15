#!/usr/bin/env bash
# Run ON the SOC controller VM103 (192.168.40.10) as root.
# Installs Ollama, exposes it on :11434 for the honeypots, pulls candidate models.
#
#   git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis
#   bash /opt/netosis/scripts/soc-setup.sh
#   python3 /opt/netosis/scripts/llm_bench.py        # pick the model
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Re-run as root." >&2
  exit 1
fi

MODELS="${MODELS:-qwen2.5:0.5b qwen2.5:1.5b qwen2.5:3b}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl git python3 >/dev/null

echo "[*] CPU flags (X5650 has no AVX — Ollama falls back to the generic CPU build):"
grep -o -w -E 'avx|avx2|sse4_2' /proc/cpuinfo | sort -u | tr '\n' ' '; echo

if ! command -v ollama >/dev/null; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

# Listen on all interfaces so honeypots in VLAN 10/20/30 can reach it
# (OPNsense + Proxmox FW restrict who actually can).
mkdir -p /etc/systemd/system/ollama.service.d
cat >/etc/systemd/system/ollama.service.d/netosis.conf <<'EOF'
[Service]
Environment=OLLAMA_HOST=0.0.0.0:11434
Environment=OLLAMA_KEEP_ALIVE=24h
Environment=OLLAMA_NUM_PARALLEL=2
EOF
systemctl daemon-reload
systemctl enable --now ollama
systemctl restart ollama
sleep 3

for m in $MODELS; do
  echo "[*] Pulling $m"
  ollama pull "$m"
done

echo
echo "[+] Ollama listening on :11434"
ss -ltnp | grep 11434 || true
echo "    Next: python3 $(dirname "$0")/llm_bench.py"
