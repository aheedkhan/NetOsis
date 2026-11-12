#!/usr/bin/env bash
# Check one lab node is installed safely (run as root ON a honeypot CT or the SOC VM).
#
#   bash /opt/netosis/scripts/lab-verify.sh
#
# FAIL = broken or unsafe, fix before going live.  WARN = a firewall rule or
# setting you should look at (some only make sense after the install window).
# Exit code is non-zero when anything FAILs. Never changes anything.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOC_IP="${NETOSIS_SOC_IP:-192.168.40.31}"
PASS=0; WARN=0; FAIL=0
ok()   { echo "  [ok]   $*"; PASS=$((PASS+1)); }
warn() { echo "  [warn] $*"; WARN=$((WARN+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
check(){ local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
reach(){ curl -s -o /dev/null -m 4 "$1"; }  # true if a TCP+HTTP(S) answer came back

[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root" >&2; exit 2; }
if [[ -f /etc/systemd/system/netosis-controller.service ]]; then ROLE=soc
elif [[ -f /etc/systemd/system/netosis-ssh.service ]]; then ROLE=honeypot
else ROLE=other; fi
perm() { stat -c '%U:%G %a' "$1" 2>/dev/null; }
echo "NetOsis check on $(hostname) (role: $ROLE)"

echo "- node agent"
check "netosis-agent is running" systemctl is-active --quiet netosis-agent
PID="$(systemctl show -p MainPID --value netosis-agent 2>/dev/null || echo 0)"
if [[ "$PID" != "0" ]] && ss -Hltunp 2>/dev/null | grep -q "pid=$PID,"; then
  bad "agent has a listening socket (it must only send)"
else ok "agent listens on nothing"; fi
[[ "$(perm /etc/netosis)" == "root:root 700" ]] && ok "/etc/netosis is root 700" || bad "/etc/netosis is $(perm /etc/netosis), want root:root 700"
[[ "$(perm /etc/netosis/agent.env)" == "root:root 600" ]] && ok "agent.env is root 600" || bad "agent.env is $(perm /etc/netosis/agent.env), want root:root 600"
grep -qE '^NETOSIS_NODE_KEY=[0-9a-f]{64}$' /etc/netosis/agent.env 2>/dev/null && ok "agent signs with its own node key" || bad "agent.env has no NETOSIS_NODE_KEY"
grep -q '^NETOSIS_INGEST_TOKEN=' /etc/netosis/agent.env 2>/dev/null && bad "agent.env still holds the master token" || ok "agent.env holds no master token"
if id netosis >/dev/null 2>&1; then
  runuser -u netosis -- test -r /etc/netosis/agent.env 2>/dev/null && bad "the honeypot user can read agent.env" || ok "the honeypot user cannot read agent.env"
fi
if journalctl -u netosis-agent --since "-2min" --no-pager 2>/dev/null | grep -q "report failed"; then
  warn "agent reports failed in the last 2 min:  journalctl -u netosis-agent -n 20"
else ok "agent reports going through (no failures in 2 min)"; fi

if [[ "$ROLE" == "honeypot" ]]; then
  echo "- honeypot"
  check "netosis-ssh is running" systemctl is-active --quiet netosis-ssh
  ss -Hltn | awk '{print $4}' | grep -qE ':2222$' && ok "honeypot listens on :2222" || bad "nothing on :2222"
  [[ "$(perm "$ROOT/.env")" == "netosis:netosis 600" ]] && ok ".env is netosis 600" || bad ".env is $(perm "$ROOT/.env"), want netosis:netosis 600"
  grep -qE '^NETOSIS_NODE_KEY=[0-9a-f]{64}$' "$ROOT/.env" && ok "honeypot signs with its own node key" || bad ".env has no NETOSIS_NODE_KEY"
  grep -q '^NETOSIS_INGEST_TOKEN=' "$ROOT/.env" && bad ".env still holds the lab master token" || ok "no master token on this honeypot"
  grep -q '^NETOSIS_LLM_DEMO_MARK=1' "$ROOT/.env" && warn "[llm] demo mark is ON (fine for the viva; set 0 for real attackers)"

  echo "- what else listens here (attackers reach this CT only through the NAT to :2222)"
  others="$(ss -Hltn | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|::1)' | grep -vE ':2222$' | sort -u | tr '\n' ' ')"
  [[ -z "$others" ]] && ok "only :2222 is open to the network" || warn "also listening: $others (real sshd? stop it: systemctl disable --now ssh — use 'pct enter' instead)"

  echo "- paths (needs the OPNsense rules in docs/DEPLOY-lab.md)"
  reach "http://$SOC_IP:8001/healthz" && ok "ingest $SOC_IP:8001 reachable" || bad "cannot reach ingest $SOC_IP:8001 (telemetry won't arrive)"
  reach "http://$SOC_IP:8000/" && warn "dashboard $SOC_IP:8000 is reachable from this honeypot — block it on OPNsense" || ok "dashboard :8000 not reachable from here"
  gw="$(ip route show default 2>/dev/null | awk '{print $3; exit}')"
  if [[ -n "$gw" ]]; then
    { reach "https://$gw/" || reach "http://$gw/"; } && warn "firewall web GUI on $gw answers from this honeypot — block it" || ok "firewall GUI not reachable from here"
  fi
  reach "https://1.1.1.1/" && warn "this CT can reach the Internet (OK only during install; then close it)" || ok "no Internet egress"

  echo "- attacker's view (fake shell must show nothing of the lab)"
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    if out="$(cd "$ROOT" && "$ROOT/.venv/bin/python" -m pytest -q -p no:cacheprovider tests/unit/test_shell_hides_lab.py 2>&1)"; then ok "fake shell hides the agent, controller and real IPs"
    else bad "fake shell leaks lab details:"; echo "$out" | grep -E "reveals|Error" | head -5; fi
  else warn "no venv yet, skipped the fake-shell leak check"; fi
fi

if [[ "$ROLE" == "soc" ]]; then
  echo "- controller"
  ENV="$ROOT/controller/.env"
  check "netosis-controller is running" systemctl is-active --quiet netosis-controller
  [[ "$(perm "$ENV")" == "netosis:netosis 600" ]] && ok "controller/.env is netosis 600" || bad "controller/.env is $(perm "$ENV"), want netosis:netosis 600"
  grep -q '^NETOSIS_REQUIRE_SIGNED=1' "$ENV" && ok "signed node requests required" || bad "NETOSIS_REQUIRE_SIGNED=1 missing in controller/.env"
  for p in 8000 8001; do reach "http://127.0.0.1:$p/healthz" && ok "answers on :$p" || bad "nothing on :$p"; done
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 4 -X POST -H 'Content-Type: application/json' -H 'X-Netosis-Probe: lab-verify' -d '{}' "http://127.0.0.1:8001/v1/agent")"
  [[ "$code" == "401" ]] && ok "unsigned writes are refused (401)" || bad "unsigned POST /v1/agent got $code, want 401"
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 4 "http://127.0.0.1:8001/api/overview")"
  [[ "$code" == "404" ]] && ok "ingest port serves no dashboard data" || bad "ingest port served /api/overview ($code)"
  [[ -f /root/netosis-node-keys.env ]] && warn "/root/netosis-node-keys.env still here — delete it once lab-rollout.sh is done"
  online="$(curl -s -m 4 http://127.0.0.1:8000/api/agents | python3 -c 'import json,sys; a=json.load(sys.stdin); a=a.get("agents",a) if isinstance(a,dict) else a; print(sum(1 for x in a if x.get("online") and not x.get("demo")))' 2>/dev/null || echo "?")"
  ok "real node agents online: $online (expect 4 once every CT is installed)"
  timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes && ok "clock is NTP-synced" || warn "clock not NTP-synced: signed requests fail beyond 90 s of drift"
fi

echo "result: $PASS ok, $WARN warn, $FAIL fail"
[[ "$FAIL" -eq 0 ]]
