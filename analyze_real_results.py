#!/usr/bin/env python3
"""Compute mean/SD/median/p95 from kali_real_results.csv produced by
kali_real_trials.sh. Run on Kali (or copy the CSV anywhere with Python 3).

Usage: python3 analyze_real_results.py kali_real_results.csv
"""
import csv
import statistics
import sys


def stats(vals):
    vals = sorted(vals)
    if not vals:
        return None
    return {
        "n": len(vals),
        "mean": statistics.mean(vals),
        "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        "median": statistics.median(vals),
        "p95": vals[min(len(vals) - 1, int(0.95 * len(vals)))],
        "min": vals[0],
        "max": vals[-1],
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "kali_real_results.csv"
    total_ms, post_ms = [], []
    redirected = 0
    total_trials = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            total_trials += 1
            if row["status"] == "redirected":
                redirected += 1
                total_ms.append(float(row["elapsed_total_ms"]))
                post_ms.append(float(row["elapsed_post_attempts_ms"]))

    print(f"Trials: {total_trials}, redirected successfully: {redirected} "
          f"({100 * redirected / total_trials:.1f}%)")
    print("\n-- elapsed_total_ms (first failed attempt -> trap access) --")
    print(stats(total_ms))
    print("\n-- elapsed_post_attempts_ms (after 3rd failed attempt -> trap access) --")
    print(stats(post_ms))


if __name__ == "__main__":
    main()
