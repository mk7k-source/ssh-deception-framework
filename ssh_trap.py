#!/usr/bin/env python3
"""
ssh_trap.py

Low-interaction SSH trap used as the redirect target of active_deception_guard.py.

Isolation model
---------------
* Attacker input is NEVER executed. Commands are matched against a small table
  of canned responses; everything else returns "command not found".
  There is no real shell, no filesystem access and no outbound network access.
* Run it as an unprivileged user on a high port (default 2222); the guard's
  iptables REDIRECT rule maps port 22 -> 2222 for diverted sources only.
* Session length, command count and line length are capped.

Logging
-------
One JSON object per line: session start/end, authentication attempts and every
command line, each with a nanosecond timestamp and source address.
Granularity is the *command line*, not individual key presses (see paper).

Requires: pip install paramiko
"""
import argparse
import json
import os
import socket
import threading
import time

import paramiko

BANNER_HOST = "web-prod-03"
CANNED = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux web-prod-03 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "uname": "Linux",
    "pwd": "/root",
    "hostname": BANNER_HOST,
    "ls": "backup.tar.gz  notes.txt",
    "w": " 12:00:01 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01",
}


class JsonLog:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, **fields):
        fields.setdefault("ts_ns", time.time_ns())
        line = json.dumps(fields, sort_keys=True)
        with self.lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class TrapServer(paramiko.ServerInterface):
    def __init__(self, peer, log):
        self.peer = peer
        self.log = log
        self.shell_event = threading.Event()

    def check_auth_password(self, username, password):
        # Credentials are recorded; any pair is accepted to keep the attacker engaged.
        self.log.write(event="auth", src=self.peer, user=username, password=password)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace")
        self.log.write(event="exec", src=self.peer, command=cmd)
        channel.send(respond(cmd) + "\r\n")
        channel.send_exit_status(0)
        self.shell_event.set()
        return True


def respond(cmd):
    cmd = cmd.strip()
    if cmd in CANNED:
        return CANNED[cmd]
    if cmd.startswith("cd") or cmd == "":
        return ""
    return f"bash: {cmd.split()[0]}: command not found"


def shell_loop(chan, peer, log, max_cmds, max_secs, max_line):
    start = time.monotonic()
    count = 0
    chan.send(f"Welcome to Ubuntu 22.04.3 LTS\r\n\r\nroot@{BANNER_HOST}:~# ")
    buf = ""
    chan.settimeout(1.0)
    while time.monotonic() - start < max_secs and count < max_cmds:
        try:
            data = chan.recv(256)
        except socket.timeout:
            continue
        if not data:
            break
        for ch in data.decode("utf-8", "replace"):
            if ch in ("\r", "\n"):
                chan.send("\r\n")
                line = buf
                buf = ""
                log.write(event="command", src=peer, command=line)
                count += 1
                if line.strip() in ("exit", "logout"):
                    return count
                out = respond(line)
                if out:
                    chan.send(out + "\r\n")
                chan.send(f"root@{BANNER_HOST}:~# ")
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":
                buf = ""
                chan.send("^C\r\n" + f"root@{BANNER_HOST}:~# ")
            elif ch.isprintable() and len(buf) < max_line:
                buf += ch
                chan.send(ch)
    return count


def handle(client, addr, host_key, log, args):
    peer = addr[0]
    log.write(event="session_start", src=peer, sport=addr[1])
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    server = TrapServer(peer, log)
    n = 0
    try:
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is not None and server.shell_event.wait(10):
            if not chan.closed and chan.active:
                n = shell_loop(chan, peer, log, args.max_commands,
                               args.max_seconds, args.max_line)
            chan.close()
    except Exception as exc:  # noqa: BLE001 - trap must never crash
        log.write(event="session_error", src=peer, error=repr(exc))
    finally:
        log.write(event="session_end", src=peer, commands=n)
        transport.close()


def load_host_key(path):
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    os.chmod(path, 0o600)
    return key


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--host-key", default="trap_host_rsa.key")
    ap.add_argument("--session-log", default="trap_sessions.jsonl")
    ap.add_argument("--max-commands", type=int, default=200)
    ap.add_argument("--max-seconds", type=int, default=600)
    ap.add_argument("--max-line", type=int, default=512)
    ap.add_argument("--max-sessions", type=int, default=20)
    args = ap.parse_args()

    log = JsonLog(args.session_log)
    host_key = load_host_key(args.host_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(50)
    slots = threading.BoundedSemaphore(args.max_sessions)
    print(f"[trap] listening on {args.bind}:{args.port}", flush=True)
    while True:
        client, addr = sock.accept()
        if not slots.acquire(blocking=False):
            client.close()
            continue

        def run(c=client, a=addr):
            try:
                handle(c, a, host_key, log, args)
            finally:
                slots.release()
        threading.Thread(target=run, daemon=True).start()


if __name__ == "__main__":
    main()
