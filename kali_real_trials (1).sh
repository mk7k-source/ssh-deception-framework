#!/usr/bin/env bash
# kali_real_trials.sh
#
# Runs on the Kali VM. Performs N real, independent brute-force trials
# against the Ubuntu target over the actual network (not log injection).
# Each trial uses a FRESH source IP alias on this VM's interface, so each
# one is an independent detection event for the guard (no reused IP, no
# stale NAT rule skipping).
#
# Per trial:
#   1. Adds a new alias IP (192.168.56.<101+i>) to the interface.
#   2. Makes 3 real SSH connection attempts with a WRONG password
#      (should hit the real sshd and fail -- this is what the guard's
#      detector sees in /var/log/auth.log on the target).
#   3. Polls (every 0.2 s, up to 8 s) with a login attempt using ANY
#      password and runs `whoami` remotely. The real sshd would still
#      reject this; the trap accepts any password and returns "root".
#      The first poll that returns "root" with exit code 0 marks the
#      moment the attacker was successfully diverted into the trap.
#   4. Records elapsed time (ms) from the first failed attempt to that
#      success, and removes the alias IP.
#
# Requirements: sshpass, an OpenSSH client that supports `-b` (bind
# address), and passwordless sudo for `ip addr add/del` (default on Kali).
#
# Usage:
#   chmod +x kali_real_trials.sh
#   ./kali_real_trials.sh 192.168.56.10 eth1 30
set -u

TARGET="${1:-192.168.56.10}"
IFACE="${2:-eth1}"
TRIALS="${3:-30}"
BASE_OCTET=100
OUT="kali_real_results.csv"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=no"

command -v sshpass >/dev/null 2>&1 || sudo apt-get update -qq && sudo apt-get install -y sshpass

echo "trial,ip,status,elapsed_total_ms,elapsed_post_attempts_ms" > "$OUT"

for i in $(seq 1 "$TRIALS"); do
  ALIAS="192.168.56.$((BASE_OCTET + i))"
  sudo ip addr add "$ALIAS/24" dev "$IFACE" 2>/dev/null

  t0=$(date +%s%N)
  for attempt in 1 2 3; do
    sshpass -p "wrongpass_${attempt}" ssh -b "$ALIAS" $SSH_OPTS \
      admin@"$TARGET" exit >/dev/null 2>&1
    sleep 0.2
  done
  t_after_attempts=$(date +%s%N)

  status="timeout"
  t_success=0
  deadline=$(( $(date +%s) + 8 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    out=$(sshpass -p "anypassword" ssh -b "$ALIAS" $SSH_OPTS \
      admin@"$TARGET" "whoami" 2>/dev/null)
    rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "root" ]; then
      t_success=$(date +%s%N)
      status="redirected"
      break
    fi
    sleep 0.2
  done

  if [ "$status" = "redirected" ]; then
    elapsed_total_ms=$(( (t_success - t0) / 1000000 ))
    elapsed_post_ms=$(( (t_success - t_after_attempts) / 1000000 ))
  else
    elapsed_total_ms="NA"
    elapsed_post_ms="NA"
  fi

  echo "$i,$ALIAS,$status,$elapsed_total_ms,$elapsed_post_ms" >> "$OUT"
  echo "[trial $i] ip=$ALIAS status=$status total_ms=$elapsed_total_ms post_ms=$elapsed_post_ms"

  sudo ip addr del "$ALIAS/24" dev "$IFACE" 2>/dev/null
done

echo
echo "Done. Raw results: $OUT"
