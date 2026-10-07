#!/usr/bin/env python3
"""Long Exposure round 4: two-time-pad test.

Hypothesis from field-note.txt ("Original and processed takes were exported
together"): the core/noise holds two (or more) copies of the same plaintext,
so their XOR is the keystream.  Test keystream = A[o1:o1+72] XOR B[o2:o2+72]
for every pair of windows in core / noi / pcap (both orientations), screened
by the 7-byte crib and verified against the full `safctf{64hex}` structure.
"""
import base64, struct

IDS = {0: "PZRA3C5MF2WARTI", 1: "6CYYWT3ECKT45IY", 2: "B256MK23FAQL2VY",
       3: "PVC46ZEQQHTN7UI", 4: "FJQLJ6KV2NM66HY", 5: "BZDPUAPZ44P4WHQ",
       6: "4N6YDDXKVZSNSDI", 7: "UORLITSJBNLJVUI"}

core = open("process.core", "rb").read()
raw = open("uplink.pcap", "rb").read()
off = 24
pkts = []
while off + 16 <= len(raw):
    ts, tus, incl, orig = struct.unpack("<IIII", raw[off:off + 16]); off += 16
    pkts.append(raw[off:off + incl]); off += incl
noi = b"".join(p[3:] for p in pkts if p[:3] == b"NOI")

C = b"".join(base64.b32decode(IDS[i] + "=") for i in range(8))
CRIB = bytes(a ^ b for a, b in zip(C[:7], b"safctf{"))
HEX = set(range(0x30, 0x3a)) | set(range(0x61, 0x67))


def ok(pt):
    return (len(pt) == 72 and pt[:7] == b"safctf{"
            and all(c in HEX for c in pt[7:71]) and pt[71:72] == b"}")


def scan(a, b):
    hits = 0
    for ai, aa in enumerate((a, a[::-1])):
        for bi, bb in enumerate((b, b[::-1])):
            idx = {}
            for o in range(len(bb) - 6):
                idx.setdefault(bb[o:o + 7], []).append(o)
            for o1 in range(len(aa) - 71):
                key = bytes(x ^ y for x, y in zip(aa[o1:o1 + 7], CRIB))
                for o2 in idx.get(key, ()):
                    if o2 + 72 > len(bb):
                        continue
                    ks = bytes(x ^ y for x, y in zip(aa[o1:o1 + 72], bb[o2:o2 + 72]))
                    pt = bytes(x ^ y for x, y in zip(C, ks))
                    if ok(pt):
                        print("*** HIT", ai, o1, bi, o2, pt); hits += 1
                    elif pt[:7] == b"safctf{":
                        print("partial", ai, o1, bi, o2, pt); hits += 1
    return hits


srcs = {"core": core, "noi": noi, "pcap": raw}
tot = 0
for n1, a in srcs.items():
    for n2, b in srcs.items():
        h = scan(a, b)
        print(f"{n1} x {n2}: crib-screened candidates {h}")
        tot += h
print("total", tot)
