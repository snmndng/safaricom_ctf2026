---
title: "Pixel Courier"
ctf: "Safaricom CTF"
date: 2026-10-06
category: reverse
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "Strawhats"
---

# Pixel Courier

> **Category:** REV · **Points:** 150 · **Difficulty:** easy

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

## Target
- Page: http://54.72.82.22:8510/ (title "Pixel Courier", the only download link is `receipt`).
- Artifact: `GET /downloads/receipt` → 14520 bytes.
  - `file`: ELF 64-bit LSB executable, x86-64, dynamically linked,
    interpreter `/lib64/ld-linux-x86-64.so.2`, **stripped**, GCC 14.2.0.
  - sha256 `846fd968cdf2ca9493bbd29e678217c6c56213ac059cf299ebc16963830bb50d`
  - size 14520 bytes (not committed — `.gitignore` blocks binaries; fetch with solve.py).

## Note on the hint
The triage hint suggested "image/PNG-based flag encoding". That was **wrong** for this
challenge — the downloadable artifact is a native ELF, not an image. No PNG/stego work was
needed. (The name/theme is just flavor: "Pixel Courier".)

## Reverse engineering
Entry `_start` @ `0x401080` passes `main` @ `0x4011e4`. Only two libc calls matter
(`fgets`, `strcspn`, `strlen`, `putchar`, `puts`). Two user functions:
- `main` @ `0x4011e4` — the checker.
- render `0x401166` — prints the flag when the check passes.

### Checker (`main`)
1. `puts` prompt, `fgets(buf, 0x80, stdin)`, strip `\n` via `strcspn` delimiter at `0x402011`.
2. `strlen(buf)` must equal `0x18` = **24**.
3. Two 24-byte tables built on the stack via `movabs` immediates:
   - `T1` (`rbp-0xb0`) — a **permutation of 0..23**, indexes into the input.
   - `T2` (`rbp-0xd0`) — target byte values.
4. For `i` in `0..23`:
   ```
   out  = ((13*i + 0x5b) ^ buf[T1[i]]) + i     # compared as an 8-bit (dl) value
   fail if low8(out) != T2[i]
   ```

### Inverting the check (all mod 256)
```
(P ^ buf[T1[i]]) == (T2[i] - i)     with P = (13*i + 0x5b) & 0xff
=>  buf[T1[i]] = P ^ ((T2[i] - i) & 0xff)
```
Accepted input: `DWT8V52N2HLTUQE6CPGBQMJJ` (24 chars).

### Flag printer (`0x401166`)
When the check passes, `main` calls `0x401166` with `rdi = buf`:
```
key = 44-byte blob @ 0x404060 (.data)
for i in 0..43: putchar(key[i] ^ buf[i % 24])
```
The 44 printed bytes are exactly the flag (44 chars). Extracting `key` from `.data`
and XOR-ing against the repeating 24-byte input yields:
`safctf{e7802274-4b04-488a-9319-39ca86e83c9f}`

## Verification
Ran the real binary:
```
$ echo "DWT8V52N2HLTUQE6CPGBQMJJ" | ./receipt
Parcel desk
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}     # exit 0
$ echo "wrongtest" | ./receipt
Parcel desk                                        # exit 1
```

## Tools used
`curl`, `readelf`, `objdump -d -M intel`, `strings`, Python 3 (stdlib only) for the solve.

## Files
- `solve.py` — fetches `/downloads/receipt`, parses T1/T2/key straight from the ELF
  (with recorded-constant fallback), and prints the flag.
- `receipt.bin` / `receipt` — fetched artifact (untracked; binary).

## Solve script

`rev/pixel-courier/solve.py`:

```python
#!/usr/bin/env python3
"""Pixel Courier (safaricom CTF, REVERSE 150) solver.

Fetches /downloads/receipt (a stripped x86-64 ELF) and derives the flag.

Binary logic (reversed from objdump):

  main():
    puts("Parcel desk"); fgets(buf, 0x80, stdin); strip '\n';
    if strlen(buf) != 24: exit(1)
    T1 = permutation table @ rbp-0xb0 (24 bytes, perm of 0..23)
    T2 = target table       @ rbp-0xd0 (24 bytes)
    for i in 0..23:
        out = ((13*i + 0x5b) ^ buf[T1[i]]) + i          # 8-bit low byte
        if low8(out) != T2[i]: exit(1)

  render(buf):                       # called only when the check passes
    key = 44-byte blob @ 0x404060
    for i in 0..43:
        putchar(key[i] ^ buf[i % 24])   # -> the 44-char flag

Solving the check for buf (all arithmetic mod 256):

    (P ^ buf[T1[i]]) == (T2[i] - i)   with P = (13*i + 0x5b) & 0xff
    buf[T1[i]] = P ^ ((T2[i] - i) & 0xff)

Then the printed output is exactly the flag.
"""

import sys
import urllib.request

URL = "http://54.72.82.22:8510/downloads/receipt"

# Fallback constants (verified identical to the values parsed out of the ELF).
FALLBACK_T1 = bytes([0x00, 0x0a, 0x04, 0x05, 0x07, 0x02, 0x0b, 0x03,
                     0x11, 0x14, 0x12, 0x13, 0x0d, 0x10, 0x09, 0x0e,
                     0x0c, 0x08, 0x15, 0x17, 0x16, 0x01, 0x0f, 0x06])
FALLBACK_T2 = bytes([0x1f, 0x25, 0x25, 0xba, 0xc5, 0xcd, 0x03, 0x95,
                     0x9b, 0x8a, 0xa4, 0xb3, 0xb2, 0x54, 0x67, 0x6a,
                     0x8e, 0x1b, 0x1a, 0x2b, 0x29, 0x50, 0x65, 0xcb])
FALLBACK_KEY = bytes([0x37, 0x36, 0x32, 0x5b, 0x22, 0x53, 0x49, 0x2b,
                      0x05, 0x70, 0x7c, 0x66, 0x67, 0x66, 0x71, 0x1b,
                      0x77, 0x32, 0x77, 0x76, 0x7c, 0x79, 0x72, 0x72,
                      0x25, 0x7a, 0x6d, 0x0b, 0x67, 0x0c, 0x1f, 0x7d,
                      0x0b, 0x2b, 0x2d, 0x6c, 0x63, 0x34, 0x7d, 0x05,
                      0x20, 0x69, 0x21, 0x3f])


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def parse_tables(elf):
    """Pull T1/T2/key straight out of the ELF at their known vaddrs.

    Each table entry is an imm64 embedded in a `movabs` (48 b8 / 48 ba);
    the 44-byte key lives in .data. vaddr->file-offset is resolved through the
    section header table (.text and .data load at different bases).
    """
    # minimal ELF64 section-header walk to map vaddr -> file offset
    e_shoff = int.from_bytes(elf[0x28:0x30], "little")
    e_shentsize = int.from_bytes(elf[0x3A:0x3C], "little")
    e_shnum = int.from_bytes(elf[0x3C:0x3E], "little")
    secs = []
    for i in range(e_shnum):
        p = e_shoff + i * e_shentsize
        sh_addr = int.from_bytes(elf[p + 0x10:p + 0x18], "little")
        sh_offset = int.from_bytes(elf[p + 0x18:p + 0x20], "little")
        sh_size = int.from_bytes(elf[p + 0x20:p + 0x28], "little")
        secs.append((sh_addr, sh_offset, sh_size))

    def at(vaddr, n):
        for addr, off, size in secs:
            if addr and addr <= vaddr < addr + size:
                return elf[off + (vaddr - addr):off + (vaddr - addr) + n]
        return b""

    t1 = at(0x4011f1, 8) + at(0x4011fb, 8) + at(0x401213, 8)
    t2 = at(0x401224, 8) + at(0x40122e, 8) + at(0x401246, 8)
    key = at(0x404060, 44)
    if not (sorted(t1) == list(range(24)) and len(t2) == 24 and len(key) == 44):
        raise ValueError("table parse mismatch")
    return t1, t2, key


def solve(t1, t2, key):
    buf = bytearray(24)
    for i in range(24):
        p = (13 * i + 0x5B) & 0xFF
        y = (t2[i] - i) & 0xFF
        buf[t1[i]] = p ^ y
    return bytes(key[i] ^ buf[i % 24] for i in range(44))


def main():
    try:
        elf = fetch(URL)
        t1, t2, key = parse_tables(elf)
        print(f"[+] fetched {len(elf)} bytes; parsed tables from ELF",
              file=sys.stderr)
    except Exception as e:  # offline / layout drift -> use recorded constants
        print(f"[!] live parse failed ({e}); using fallback constants",
              file=sys.stderr)
        t1, t2, key = FALLBACK_T1, FALLBACK_T2, FALLBACK_KEY

    flag = solve(t1, t2, key)
    print(flag.decode())


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `urllib` (stdlib HTTP client)
- Python 3 (solver)
- curl
- objdump
- readelf

**Other tools that fit this category:**

- Ghidra / IDA Free (decompile)
- radare2 / rizin (+ Cutter)
- angr (symbolic execution)
- GDB (dynamic)
- dnSpy (.NET), uncompyle6 (Python)
- Binary Ninja

## Flag

```
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}
```
