# On-Demand SSH Deception for Linux Servers

Reference implementation and evaluation scripts for the paper *"On-Demand SSH
Deception for Linux Servers: Coupling Authentication-Log Monitoring with
Automated Honeypot Diversion."*

A sliding-window detector reads `/var/log/auth.log` (or journald) and, when a
source address exceeds *K* failed SSH logins within *T* seconds, installs a
time-limited `iptables` NAT rule that diverts that address's subsequent SSH
connections to a low-interaction trap. The trap never executes attacker
input; it logs credentials and every command line with nanosecond timestamps.

## Files

| File | Purpose |
|---|---|
| `active_deception_guard.py` | Detector + diversion controller (run as root) |
| `ssh_trap.py` | Low-interaction SSH trap (run as an unprivileged user) |
| `run_experiments.py` | Controlled pipeline-latency harness (synthetic log injection) |
| `fpr_test.py` | Detection-quality boundary-check harness (false-positive test) |
| `kali_real_trials.sh` | Real-network attack trial script (run on an attacker VM) |
| `analyze_real_results.py` | Computes stats from `kali_real_trials.sh` output |
| `paper_FINAL.md` / `SSH_Deception_Paper.docx` | The paper |

## Quick start

```bash
# Trap (unprivileged)
python3 -m venv venv && venv/bin/pip install paramiko
venv/bin/python ssh_trap.py --port 2222

# Guard (root)
sudo python3 active_deception_guard.py \
  --source file --log /var/log/auth.log \
  --whitelist 127.0.0.0/8,<your-admin-ip> \
  --event-log /var/log/active_deception/events.jsonl
```

Dry-run (no root, no iptables, for testing the detection logic only):

```bash
printf '%s\n' "Failed password for root from 203.0.113.9 port 1 ssh2" \
  | python3 active_deception_guard.py --source stdin --dry-run
```

See the paper's Sections III–IV for the full design and Section VI for the
evaluation methodology and results reproduced by the scripts above.

## License

Add a license (e.g., MIT or Apache-2.0) before public release.

## Citation

If you use this code, please cite the accompanying paper (details to be
added once published).
