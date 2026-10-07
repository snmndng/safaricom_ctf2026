---
title: "Prism Orchestra"
ctf: "Safaricom CTF"
date: 2026-10-06
category: reverse
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "Strawhats"
---

# Prism Orchestra

> **Category:** REV · **Points:** 750 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

## Material

- Server: `http://54.72.82.22:8530` (Werkzeug/Flask), page offers two downloads:
  - `/downloads/receipt` — stripped Linux x86-64 ELF, no extension
    sha256 `6549b17ee5a07af02702ca7c6c1e54408054007c2a37548d7b12f8029c227007`
  - `/downloads/score.bin` — 540-byte bytecode blob
    sha256 `16be4ea7319b9c385900cbe97a718ac2f8e00d40addf3ece4ee072dc8d710892`
- Neither binary is committed (ELF kept out of git via `.gitignore`; `*.bin`
  already ignored). `solve.py` embeds `score.bin` so it runs standalone.

## Structure

`receipt` is 1.5 KB and does all of this in `main` (0x401224):

1. `fgets` 24 chars from stdin, newline stripped, `strlen == 0x18` required.
   That 24-byte buffer is the VM's register file (mem[0..23]).
2. Opens `/app/downloads/score.bin`; loop reads 3 bytes per instruction —
   `opcode, a, b` (`a` validated `0..0x17`, `b` `0..255`) — and applies:
   - `1`: `mem[a] ^= b`
   - `2`: `mem[a] += b` (mod 256)
   - `3`: `mem[a] = rol8(mem[a], (b % 7) + 1)`  (the `*0x92492493` + `% 7` code
     is just `b % 7`; the shift pair is a byte rotate)
   - `4`: `swap(mem[a], mem[b % 24])`  (`b - 24*int(b/24)`)
   - anything else → return code 3 (error)
3. `memcmp(mem, TARGET, 24)` against
   `49 2e 0d 7f df 2a 96 8d | 77 f1 e1 6e ab f1 37 a3 | 96 ab 62 07 85 5d eb 6d`
   (three `movabs` at 0x40122f/0x401239/0x401251).
4. On success calls 0x4011a6, which prints
   `TABLE[i] ^ mem[i % 24]` for a 44-byte table at `.data:0x404080`
   (`37 25 36 36 ... 04 60 2d`). That XOR stream is the flag.

`score.bin` = 180 instructions, opcodes {1:53, 4:52, 3:39, 2:36}, `a` in 0..23.

## Technique

No solver/emulator needed — every opcode is invertible and the program is a
straight-line sequence, so the input is recovered by walking the instruction
list **backwards** and applying the inverse of each op to `TARGET`:

    ^= b            -> ^= b            (self-inverse)
    += b            -> -= b
    rol8(x, k)      -> ror8(x, k)
    swap(a, b%24)   -> swap(a, b%24)   (self-inverse)

The resulting 24 bytes (`DDPU5WDMVRKQ2APHL7WPM78W`) are the required input;
XORing the `.data` table with `input[i % 24]` gives the flag.

## Verification

- `solve.py` forward-runs the VM on the recovered input and asserts it lands on
  `TARGET` (self-check).
- Ran the real ELF with its `/app/downloads/score.bin` path patched to a local
  copy: `printf 'DDPU5WDMVRKQ2APHL7WPM78W\n' | ./receipt_patched`
  → `Sound desk` then `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}`, rc=0.
- `POST /submit {"answer": ...}` returns `{"ok": false}` — the deployed submit
  endpoint rejects everything (likely decoy/broken, cf. the "Mr Beast
  Configuration" box). The binary's own output is the authoritative check.

## Reproduce

```
python3 solve.py
# input : DDPU5WDMVRKQ2APHL7WPM78W
# FLAG  : safctf{406279bd-3201-499f-9a4a-f14e8918eb37}
```

## Solve script

`rev/prism-orchestra/solve.py`:

```python
#!/usr/bin/env python3
"""Prism Orchestra (rev, 750) solver.

`receipt` (stripped Linux x86-64 ELF, sha256 a7619ab6...) is a tiny bytecode
VM driver.  It reads a 24-char input, runs the program in `score.bin`
(3 bytes/instruction: opcode, a, b) over a 24-byte state buffer seeded from the
input, then memcmp's it against a hardcoded 24-byte target.

Opcodes (all invertible), a in [0,23], b in [0,255]:
    1: mem[a] ^= b
    2: mem[a]  = (mem[a] + b) & 0xff
    3: mem[a]  = rol8(mem[a], (b % 7) + 1)
    4: swap(mem[a], mem[b % 24])

Inverting every op in reverse order over the target yields the required input.
On success the binary prints `table[i] ^ input[i % 24]` for the 44-byte table
at .data:0x404080 -- that XOR stream is the flag.

Verified end-to-end against the real binary (path patched to a local copy of
score.bin): input DDPU5WDMVRKQ2APHL7WPM78W -> safctf{406279bd-...-f14e8918eb37}
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# 24-byte comparison target, little-endian imm64s at main+0x0b..0x35
TARGET = bytes([0x49, 0x2e, 0x0d, 0x7f, 0xdf, 0x2a, 0x96, 0x8d,
                0x77, 0xf1, 0xe1, 0x6e, 0xab, 0xf1, 0x37, 0xa3,
                0x96, 0xab, 0x62, 0x07, 0x85, 0x5d, 0xeb, 0x6d])

# 44-byte stream XORed with the post-check input, .data:0x404080
TABLE = bytes([0x37, 0x25, 0x36, 0x36, 0x41, 0x31, 0x3f, 0x79,
               0x66, 0x64, 0x79, 0x66, 0x0b, 0x23, 0x34, 0x65,
               0x7f, 0x05, 0x67, 0x61, 0x60, 0x03, 0x01, 0x6e,
               0x22, 0x69, 0x69, 0x34, 0x01, 0x36, 0x69, 0x2b,
               0x67, 0x66, 0x2e, 0x69, 0x0b, 0x70, 0x68, 0x2d,
               0x2e, 0x04, 0x60, 0x2d])

# Embedded copy of score.bin (sha256 16be4ea7...) so the solver is standalone;
# a local score.bin overrides it if present.
PROGRAM_HEX = (
    "0102f801102c01130c0304070405040217060317c20205d701158b0400110402"
    "00030853030ac30400050113c703025f0210f0030cae0210cd040008030a6a04"
    "090e0109030206f001041b01164601168501096a020420040f00020b08040e15"
    "02140b030c6c020ea00316d00103dc041607030efc040f0b040c04030db30203"
    "b1040210030aea04161004080b0409090101390312e804060902058504081001"
    "10af03133a01085a040e0002113401050d0300a30112d5010640040809040914"
    "0401040207c80211ba0404120313fe01031e0213eb01164a01080d0314ab0316"
    "5c010f6e01145f01066a040103041003031040010fea030ab5010db80111e303"
    "00700110fe040b14020194040f020402040214ac010ae50302ab0107f40307c3"
    "0302670110330108ff030713021730010dd30404020215b5020fbd0214310117"
    "2c0400160100b40110e604071704030a0211bc01109e040b0103144b04141604"
    "0d0a01127703171c030a30010d4104130f0409080213f6040e04041315031073"
    "0306350210bd01098b011791020bb4041107040a1403082d01053e011009040d"
    "0e030d34030960040c1503147002105403125a030c17030fe00217c004021402"
    "0cf1040a0504060c010335040010010b02020efe04040502104e0115f3040603"
    "0214a204081401166c030247010dd3030a1f0110c2010e68040c120104540115"
    "c2020632020cdf020cf6010562020c5d0109a2021790040c0e040803"
)


def rol8(x, k):
    return ((x << k) | (x >> (8 - k))) & 0xFF


def ror8(x, k):
    return ((x >> k) | (x << (8 - k))) & 0xFF


def load_program():
    path = os.path.join(HERE, "score.bin")
    blob = open(path, "rb").read() if os.path.exists(path) else bytes.fromhex(PROGRAM_HEX)
    assert len(blob) % 3 == 0, "program must be 3 bytes/instruction"
    return [(blob[i], blob[i + 1], blob[i + 2]) for i in range(0, len(blob), 3)]


def step(st, op, a, b):
    """Run one VM instruction (forward direction)."""
    if op == 1:
        st[a] ^= b
    elif op == 2:
        st[a] = (st[a] + b) & 0xFF
    elif op == 3:
        st[a] = rol8(st[a], (b % 7) + 1)
    elif op == 4:
        j = b % 24
        st[a], st[j] = st[j], st[a]
    else:
        raise ValueError("unexpected opcode %d" % op)


def unstep(st, op, a, b):
    """Invert one VM instruction."""
    if op == 1:
        st[a] ^= b
    elif op == 2:
        st[a] = (st[a] - b) & 0xFF
    elif op == 3:
        st[a] = ror8(st[a], (b % 7) + 1)
    elif op == 4:
        j = b % 24
        st[a], st[j] = st[j], st[a]
    else:
        raise ValueError("unexpected opcode %d" % op)


def solve(program):
    st = bytearray(TARGET)
    for op, a, b in reversed(program):
        unstep(st, op, a, b)
    return bytes(st)


def main():
    prog = load_program()
    inp = solve(prog)
    # sanity: forward-run the VM, confirm it lands on TARGET
    st = bytearray(inp)
    for op, a, b in prog:
        step(st, op, a, b)
    assert bytes(st) == TARGET, "inverse failed"
    flag = bytes(TABLE[i] ^ inp[i % 24] for i in range(len(TABLE))).decode()
    print("input :", inp.decode())
    print("FLAG  :", flag)


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python 3 (solver)

**Other tools that fit this category:**

- Ghidra / IDA Free (decompile)
- radare2 / rizin (+ Cutter)
- angr (symbolic execution)
- GDB (dynamic)
- dnSpy (.NET), uncompyle6 (Python)
- Binary Ninja

## Flag

```
safctf{406279bd-3201-499f-9a4a-f14e8918eb37}
```
