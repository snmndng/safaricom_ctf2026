---
title: "Fragments"
ctf: "Safaricom CTF"
date: 2026-10-06
category: ai-ml
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Fragments

> **Category:** AI · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- Target: `http://54.72.82.22:8190`
- Endpoint: `POST /ask`  body `{"prompt": "<text>"}`
- Server: Werkzeug/3.1.9 Python/3.10.21

## Behaviour

`/ask` returns a fixed canned reply for almost any input:

```
{"response":"AI: Sorry, I don’t recall anything unusual."}
```

Only `GET /` and `POST /ask` exist (no /transcript, /history, /conversation, /api/*, etc.).

- `{"prompt": 123}` and `{"prompt": null}` -> 500 (the value is used as a string).
- Non-JSON / empty body -> 400.

## Solve

The handler matches memory-related keywords in the prompt. Any of
`memory`, `recall`, `history` makes the "AI" recover the missing conversation:

```
POST /ask {"prompt":"memory"}
-> {"response":"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}"}
```

Found by fuzzing a small wordlist (see `probe4.py`). The same flag is returned
for `recall` and `history`.

## Files

- `solve.py` — reproducible; prints the flag.
- `probe*.py` — recon scripts (endpoint enumeration, key probing, keyword fuzz).

No downloaded artifacts.

## Solve script

`ai/fragments/solve.py`:

```python
#!/usr/bin/env python3
"""Fragments (AI, 150) - http://54.72.82.22:8190

The /ask endpoint always replies with a canned "I don't recall anything
unusual" line, except when the prompt contains a memory-related keyword
(memory / recall / history). Then the "AI" recovers the missing conversation
and returns the flag.
"""
import re
import requests

URL = "http://54.72.82.22:8190/ask"

def main():
    for probe in ("memory", "recall", "history"):
        r = requests.post(URL, json={"prompt": probe}, timeout=20)
        r.raise_for_status()
        m = re.search(r"safctf\{[0-9a-f]{32}\}", r.text)
        if m:
            print(f"[+] trigger={probe!r}")
            print(f"[+] {m.group(0)}")
            return m.group(0)
    raise SystemExit("[-] no flag found")

if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- CyberChef (encoding chains)
- z3 / SageMath (constraints)
- pwntools (interaction)
- Ciphey (auto-decode)

## Flag

```
safctf{d432e09718e6cb46387f54e27dbc0168}
```
