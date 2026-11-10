#!/usr/bin/env python3
"""
active_deception_guard.py

Sliding-window SSH brute-force detector that diverts offending source
addresses to a local SSH trap (ssh_trap.py) using an iptables/ip6tables
NAT REDIRECT rule. Diverted rules expire automatically (TTL).

Design notes
------------
* Only "Failed password" lines are counted. sshd emits "Invalid user" AND
  "Failed password for invalid user" for one attempt, so counting both
  would double-count.
* Only NEW connections are diverted. Already-established sessions are not
  affected (documented limitation).
* No shell is ever invoked; all external commands use argument lists.
* Every detection / redirect event is written as one JSON line so that
  detection latency (L_d) and trap deployment time (T_r) can be computed
  offline from nanosecond timestamps.

Usage (as root, for real operation):
    sudo ./active_deception_guard.py --source file --log /var/log/auth.log
    sudo ./active_deception_guard.py --source journald
Testing without root or iptables:
    printf '%s\n' "<log lines>" | ./active_deception_guard.py --source stdin --dry-run
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


def now_ns():
    return time.time_ns()


class EventLog:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, **fields):
        fields.setdefault("ts_ns", now_ns())
        line = json.dumps(fields, sort_keys=True)
        with self.lock:
            print(line, flush=True)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")


class Detector:
    """Per-IP sliding window: K failures within T seconds."""

    def __init__(self, threshold, window, max_tracked=10000):
        self.k = threshold
        self.t = window
        self.max_tracked = max_tracked
        self.hits = {}  # ip -> deque of monotonic timestamps

    def _prune(self, now):
        stale = [ip for ip, d in self.hits.items() if not d or now - d[-1] >= self.t]
        for ip in stale:
            del self.hits[ip]
        # hard cap: drop oldest-active entries if still too large
        while len(self.hits) > self.max_tracked:
            self.hits.pop(next(iter(self.hits)))

    def record(self, ip, now=None):
        """Record one failure; return True if the threshold is reached."""
        now = time.monotonic() if now is None else now
        if len(self.hits) >= self.max_tracked:
            self._prune(now)
        d = self.hits.setdefault(ip, collections.deque())
        while d and now - d[0] >= self.t:
            d.popleft()
        d.append(now)
        if len(d) >= self.k:
            del self.hits[ip]
            return True
        return False


class Redirector:
    """Adds/removes NAT REDIRECT rules for one attacker IP, with TTL."""

    def __init__(self, ssh_port, trap_port, ttl, dry_run, events):
        self.ssh_port = str(ssh_port)
        self.trap_port = str(trap_port)
        self.ttl = ttl
        self.dry_run = dry_run
        self.events = events
        self.active = {}  # ip -> expiry (monotonic)
        self.lock = threading.Lock()

    def _rule(self, ip, action):
        tool = "ip6tables" if ip.version == 6 else "iptables"
        return [tool, "-t", "nat", action, "PREROUTING", "-s", str(ip),
                "-p", "tcp", "--dport", self.ssh_port,
                "-j", "REDIRECT", "--to-ports", self.trap_port]

    def _run(self, cmd):
        if self.dry_run:
            return True
        try:
            return subprocess.run(cmd, check=True, capture_output=True,
                                  timeout=5).returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            self.events.write(event="redirect_error", cmd=cmd, error=str(exc))
            return False

    def add(self, ip):
        with self.lock:
            if ip in self.active:
                self.active[ip] = time.monotonic() + self.ttl
                return True
            ok = self._run(self._rule(ip, "-I"))
            if ok:
                self.active[ip] = time.monotonic() + self.ttl
            return ok

    def reap(self):
        now = time.monotonic()
        with self.lock:
            for ip in [i for i, exp in self.active.items() if exp <= now]:
                self._run(self._rule(ip, "-D"))
                del self.active[ip]
                self.events.write(event="redirect_expired", ip=str(ip))

    def cleanup(self):
        with self.lock:
            for ip in list(self.active):
                self._run(self._rule(ip, "-D"))
                del self.active[ip]


def open_source(args):
    if args.source == "stdin":
        return None, sys.stdin
    if args.source == "journald":
        cmd = ["journalctl", "-f", "-n", "0", "-t", "sshd", "-o", "cat"]
    else:
        if not os.path.exists(args.log):
            sys.exit(f"error: log file {args.log} not found "
                     "(use --source journald on journald-only systems)")
        cmd = ["tail", "-n", "0", "-F", args.log]  # -n 0: ignore old lines
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, errors="replace")
    return proc, proc.stdout


def parse_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", choices=["file", "journald", "stdin"], default="file")
    p.add_argument("--log", default="/var/log/auth.log")
    p.add_argument("-k", "--threshold", type=int, default=3)
    p.add_argument("-t", "--window", type=float, default=30.0)
    p.add_argument("--ttl", type=float, default=3600.0,
                   help="seconds a diverted address stays diverted")
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--trap-port", type=int, default=2222)
    p.add_argument("--whitelist", default="127.0.0.0/8,::1/128",
                   help="comma-separated IPs/CIDRs never diverted")
    p.add_argument("--event-log", default="/var/log/active_deception/events.jsonl")
    p.add_argument("--dry-run", action="store_true",
                   help="detect and log only; do not touch iptables")
    args = p.parse_args()

    if not args.dry_run and os.geteuid() != 0:
        sys.exit("error: root is required to modify iptables (use --dry-run to test)")

    whitelist = [ipaddress.ip_network(x.strip(), strict=False)
                 for x in args.whitelist.split(",") if x.strip()]
    events = EventLog(None if args.dry_run and args.event_log.startswith("/var/")
                      else args.event_log)
    detector = Detector(args.threshold, args.window)
    redirector = Redirector(args.ssh_port, args.trap_port, args.ttl,
                            args.dry_run, events)

    proc, stream = open_source(args)
    stop = threading.Event()

    def shutdown(*_):
        stop.set()
        if proc:
            proc.terminate()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def reaper():
        while not stop.wait(5):
            redirector.reap()
    threading.Thread(target=reaper, daemon=True).start()

    events.write(event="started", k=args.threshold, t=args.window,
                 ttl=args.ttl, dry_run=args.dry_run, source=args.source)
    try:
        for line in stream:
            if stop.is_set():
                break
            seen_ns = now_ns()
            m = FAILED_RE.search(line)
            if not m:
                continue
            ip = parse_ip(m.group("ip"))
            if ip is None or any(ip in net for net in whitelist):
                continue
            if detector.record(ip):
                detected_ns = now_ns()
                events.write(event="threshold_reached", ip=str(ip),
                             user=m.group("user"), line_seen_ns=seen_ns,
                             ts_ns=detected_ns)
                ok = redirector.add(ip)
                events.write(event="redirect_installed" if ok else "redirect_failed",
                             ip=str(ip), detect_to_redirect_ns=now_ns() - detected_ns)
    finally:
        redirector.cleanup()
        events.write(event="stopped")


if __name__ == "__main__":
    main()
