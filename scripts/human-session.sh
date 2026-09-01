#!/usr/bin/env bash
# A hand-paced session, run from the operator container.
#
# The counterpart to attacker-auto.sh. Where that script sweeps ports on a
# metronome, this one behaves the way a person at a terminal does: one thing at
# a time, a pause to read what came back, orientation before action, and a
# mistyped command followed by its correction. Those are exactly the signals
# lib/cs/operator.py keys on, so this is how the human branch of the policy is
# exercised without a person having to sit in the lab at the time.
set -u

DEV="${CS_TARGET_DEV:-203.0.113.20}"
WWW="${CS_TARGET_WWW:-203.0.113.10}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"

think() { sleep "$(awk -v a="$1" -v b="$2" 'BEGIN{srand();printf "%.1f",a+rand()*(b-a)}')"; }
say() { echo; echo "  [$(date +%H:%M:%S)] $*"; }

say "reading the company site"
curl -sk -m 8 -A "$UA" "https://$WWW/" | grep -o '<h1>[^<]*' | head -1
think 4 8

say "who works here"
curl -sk -m 8 -A "$UA" "https://$WWW/about.html" | grep -oE '[a-z]+\.[a-z]+@nexuscorp' | head -3
think 5 10

say "the intranet mentioned a dev host being decommissioned"
curl -sk -m 8 -A "$UA" "https://$DEV/" -o /dev/null -w "    dev portal HTTP %{http_code}\n"
think 6 11

say "it answers ssh too"
ssh $SSH_OPTS -p 22 "admin@$DEV" true 2>&1 | tail -1
think 8 14

say "trying a name from the staff page"
ssh $SSH_OPTS -p 22 "d.osei@$DEV" true 2>&1 | tail -1
think 9 15

say "and the one the announcement hinted at"
ssh $SSH_OPTS -p 22 "guest@$DEV" true 2>&1 | tail -1
think 7 12

# If the policy has opened the shell, behave like someone who just got in:
# look around, mistype something, fix it.
if command -v sshpass >/dev/null 2>&1; then
  say "if that worked, orient first"
  for cmd in "whoami" "pwd" "ls -la" "cat /etc/paswd" "cat /etc/passwd" "uname -a" "id"; do
    sshpass -p 'nexus2024' ssh $SSH_OPTS -p 22 "guest@$DEV" "$cmd" 2>/dev/null | head -2
    think 4 11
  done
fi

say "session finished"
