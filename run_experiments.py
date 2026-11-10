#!/usr/bin/env python3
"""
run_experiments.py

Repeats the detect -> redirect scenario N times against a RUNNING
active_deception_guard.py process, and computes latency statistics
for the paper's Table II.

How it works
------------
Each trial:
  1. Picks a fresh, distinct source IP in the TEST_SUBNET (so the
     guard's sliding window for each trial starts empty).
  2. Appends 3 synthetic "Failed password" lines for that IP directly
     to the auth log (simulating sshd), each a few hundred ms apart.
  3. Polls the guard's event log (events.jsonl) until it sees a
     "redirect_installed" event for that IP (or times out).
  4. Records line_seen -> threshold_reached -> redirect_installed
     deltas from the event timestamps (all nanoseconds).

This measures the GUARD's internal pipeline (log line -> detection ->
iptables rule) with a controlled, repeatable input, which is what
Table II's L_d (guard-internal) and T_r need. It does not depend on
Hydra's timing or on real network RTT, so results are much less noisy
than parsing Hydra's own output -- but you should ALSO run at least a
few real Hydra-driven trials (see run_one_real_attack.sh) to confirm
the end-to-end numbers agree.

Usage (on Ubuntu, as root, guard already running with
  --event-log /var/log/active_deception/events.jsonl
  --source file --log /var/log/auth.log):

  sudo python3 run_experiments.py --trials 30 \
      --auth-log /var/log/auth.log \
      --event-log /var/log/active_deception/events.jsonl \
      --out results.json
"""
import argparse
import json
import statistics
import time

TEST_BASE = "198.51.100."  # TEST-NET-2, reserved for documentation/testing


def tail_new_lines(path, start_pos):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(start_pos)
        data = f.read()
        return data, f.tell()


def append_failed_logins(auth_log, ip, user="admin", count=3, gap=0.05):
    with open(auth_log, "a", encoding="utf-8") as f:
        for i in range(count):
            ts = time.strftime("%b %d %H:%M:%S")
            line = (f"{ts} ubuntu sshd[{90000+i}]: Failed password for "
                    f"invalid user {user} from {ip} port {40000+i} ssh2\n")
            f.write(line)
            f.flush()
            time.sleep(gap)


def wait_for_redirect(event_log, ip, start_pos, timeout=5.0):
    """Poll the event log until redirect_installed for `ip` appears."""
    deadline = time.monotonic() + timeout
    pos = start_pos
    seen_threshold_ts = None
    while time.monotonic() < deadline:
        chunk, pos = tail_new_lines(event_log, pos)
        for line in chunk.splitlines():
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("ip") != ip:
                continue
            if ev.get("event") == "threshold_reached":
                seen_threshold_ts = ev
            if ev.get("event") == "redirect_installed":
                return seen_threshold_ts, ev, pos
        time.sleep(0.02)
    return seen_threshold_ts, None, pos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--auth-log", default="/var/log/auth.log")
    ap.add_argument("--event-log",
                    default="/var/log/active_deception/events.jsonl")
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--cooldown", type=float, default=1.0,
                    help="seconds to wait between trials")
    args = ap.parse_args()

    with open(args.event_log, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        pos = f.tell()

    results = []
    for i in range(args.trials):
        ip = f"{TEST_BASE}{10 + i}"
        t0 = time.time_ns()
        append_failed_logins(args.auth_log, ip)
        thr_ev, redir_ev, pos = wait_for_redirect(args.event_log, ip, pos)

        if thr_ev is None or redir_ev is None:
            print(f"[trial {i}] ip={ip} TIMED OUT "
                  f"(threshold_seen={thr_ev is not None}, "
                  f"redirect_seen={redir_ev is not None})")
            results.append({"ip": ip, "ok": False})
            time.sleep(args.cooldown)
            continue

        guard_internal_ns = thr_ev["ts_ns"] - thr_ev["line_seen_ns"]
        detect_to_redirect_ns = redir_ev["detect_to_redirect_ns"]
        total_ns = redir_ev["ts_ns"] - t0

        row = {
            "ip": ip,
            "ok": True,
            "guard_internal_ms": guard_internal_ns / 1e6,
            "detect_to_redirect_ms": detect_to_redirect_ns / 1e6,
            "total_ms": total_ns / 1e6,
        }
        results.append(row)
        print(f"[trial {i}] ip={ip} guard_internal={row['guard_internal_ms']:.2f} ms "
              f"detect_to_redirect={row['detect_to_redirect_ms']:.2f} ms "
              f"total={row['total_ms']:.2f} ms")
        time.sleep(args.cooldown)

    ok = [r for r in results if r["ok"]]
    summary = {}
    for key in ("guard_internal_ms", "detect_to_redirect_ms", "total_ms"):
        vals = sorted(r[key] for r in ok)
        if not vals:
            continue
        summary[key] = {
            "n": len(vals),
            "mean": statistics.mean(vals),
            "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "median": statistics.median(vals),
            "p95": vals[min(len(vals) - 1, int(0.95 * len(vals)))],
            "max": vals[-1],
            "min": vals[0],
        }

    out = {"trials": args.trials, "succeeded": len(ok),
           "failed": args.trials - len(ok), "summary": summary,
           "raw": results}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\n{len(ok)}/{args.trials} trials succeeded. Full data: {args.out}")


if __name__ == "__main__":
    main()
