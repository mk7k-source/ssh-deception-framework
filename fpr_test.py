#!/usr/bin/env python3
"""
fpr_test.py

False-positive check: simulates N benign users, each making exactly
K-1 failed login attempts (one fewer than the guard's threshold) from a
fresh source address, then succeeding. By the guard's own sliding-window
design (K failures required), none of these should trigger a redirect.
This measures whether the implementation actually matches its stated
design (TABLE IV's FPR column at the design boundary), not an open-ended
false-positive search over arbitrary benign traffic.

Also runs a handful of TRUE trials (K failures) interleaved, as a sanity
check that detection still fires normally during the same run.

Usage (on Ubuntu, as root, guard running with --event-log as below):
  sudo python3 fpr_test.py --benign 20 --malicious 5 \
      --auth-log /var/log/auth.log \
      --event-log /var/log/active_deception/events.jsonl \
      --threshold 3 --out fpr_results.json
"""
import argparse
import json
import time

BASE = "203.0.113."  # TEST-NET-3, reserved for documentation/testing


def append_lines(auth_log, ip, count, user="mustafa", gap=0.1):
    with open(auth_log, "a", encoding="utf-8") as f:
        for i in range(count):
            ts = time.strftime("%b %d %H:%M:%S")
            f.write(f"{ts} ubuntu sshd[{80000+i}]: Failed password for "
                     f"{user} from {ip} port {50000+i} ssh2\n")
            f.flush()
            time.sleep(gap)
        # simulate the eventual successful login (not matched by the
        # detector's regex, included only for log realism)
        ts = time.strftime("%b %d %H:%M:%S")
        f.write(f"{ts} ubuntu sshd[{80000+count}]: Accepted password for "
                 f"{user} from {ip} port {50000+count} ssh2\n")
        f.flush()


def saw_redirect(event_log, ip, start_pos, wait=4.0):
    deadline = time.monotonic() + wait
    with open(event_log, "r", encoding="utf-8") as f:
        f.seek(start_pos)
        while time.monotonic() < deadline:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("ip") == ip and ev.get("event") == "redirect_installed":
                return True, f.tell()
        return False, f.tell()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=20)
    ap.add_argument("--malicious", type=int, default=5)
    ap.add_argument("--auth-log", default="/var/log/auth.log")
    ap.add_argument("--event-log",
                     default="/var/log/active_deception/events.jsonl")
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--out", default="fpr_results.json")
    args = ap.parse_args()

    with open(args.event_log, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        pos = f.tell()

    results = {"benign": [], "malicious": []}

    print(f"--- {args.benign} benign trials ({args.threshold - 1} failures each) ---")
    for i in range(args.benign):
        ip = f"{BASE}{10 + i}"
        append_lines(args.auth_log, ip, args.threshold - 1)
        triggered, pos = saw_redirect(args.event_log, ip, pos, wait=3.0)
        results["benign"].append({"ip": ip, "false_positive": triggered})
        print(f"[benign {i}] ip={ip} false_positive={triggered}")

    print(f"\n--- {args.malicious} malicious trials ({args.threshold} failures each, sanity check) ---")
    for i in range(args.malicious):
        ip = f"{BASE}{100 + i}"
        append_lines(args.auth_log, ip, args.threshold, user="admin")
        triggered, pos = saw_redirect(args.event_log, ip, pos, wait=3.0)
        results["malicious"].append({"ip": ip, "detected": triggered})
        print(f"[malicious {i}] ip={ip} detected={triggered}")

    fp = sum(r["false_positive"] for r in results["benign"])
    tp = sum(r["detected"] for r in results["malicious"])
    fpr = fp / args.benign if args.benign else 0.0
    tpr = tp / args.malicious if args.malicious else 0.0

    summary = {
        "benign_trials": args.benign, "false_positives": fp, "FPR": fpr,
        "malicious_trials": args.malicious, "true_positives": tp, "TPR": tpr,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "raw": results}, f, indent=2)

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
