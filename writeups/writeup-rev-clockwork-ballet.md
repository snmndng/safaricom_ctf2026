---
title: "Clockwork Ballet"
ctf: "Safaricom CTF"
date: 2026-10-04
category: reverse
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Clockwork Ballet

## Summary

- Source: `http://54.72.82.22:8520/` ("Collection desk" -> `/downloads/receipt`)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""
Clockwork Ballet (REV 500) -- http://54.72.82.22:8520/downloads/receipt
receipt: stripped ELF x86-64.

main():
  - reads 24 bytes from stdin (strlen must == 0x18)
  - for i in {0,2,4}: tea_encrypt(buf + i*4)   # 3 x 8-byte blocks
  - memcmp(buf, target, 24) must be zero
  - then prints 44 bytes: mask[i] ^ input[i % 24]

TEA (classic, 32 rounds, delta 0x9e3779b9, sum += delta).
Invert: decrypt the 3 target blocks -> 24-byte passphrase, then XOR the mask.
"""
import struct

MASK = bytes.fromhex(
    "3b2055514733430f6b28035b5562396f5705776466026467716c0a02006d1555"
    "6c7505080b636a2104067a29"
)
TARGET = bytes.fromhex("af014942ecc411a8996696be04efb6413cf18bc31e1c3aba")
KEY = [0xe23d414a, 0xfa100e27, 0x6ac599cc, 0x0c1d1a24]
DELTA = 0x9e3779b9
M = 0xffffffff


def tea_encrypt(v0, v1, k):
    s = 0
    for _ in range(32):
        s = (s + DELTA) & M
        v0 = (v0 + ((((v1 << 4) + k[0]) & M) ^ ((v1 + s) & M) ^ (((v1 >> 5) + k[1]) & M))) & M
        v1 = (v1 + ((((v0 << 4) + k[2]) & M) ^ ((v0 + s) & M) ^ (((v0 >> 5) + k[3]) & M))) & M
    return v0, v1


def tea_decrypt(v0, v1, k):
    s = (DELTA * 32) & M
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k[2]) & M) ^ ((v0 + s) & M) ^ (((v0 >> 5) + k[3]) & M))) & M
        v0 = (v0 - ((((v1 << 4) + k[0]) & M) ^ ((v1 + s) & M) ^ (((v1 >> 5) + k[1]) & M))) & M
        s = (s - DELTA) & M
    return v0, v1


def main():
    blocks = struct.unpack("<6I", TARGET)
    pt = b""
    for j in range(0, 6, 2):
        a, b = tea_decrypt(blocks[j], blocks[j + 1], KEY)
        assert tea_encrypt(a, b, KEY) == (blocks[j], blocks[j + 1]), "round-trip failed"
        pt += struct.pack("<2I", a, b)

    print("passphrase:", pt.decode("latin1"))
    flag = bytes(MASK[i] ^ pt[i % 24] for i in range(len(MASK)))
    print("FLAG:", flag.decode())
    return flag


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{93d4bf6a-b750-4379-9038-c4921872c148}
```
