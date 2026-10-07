#!/usr/bin/env python3
"""Long Exposure round 4: periodic-keystream test under *shorter* plaintext models.

The round-2 test assumed all 72 bytes are printable.  If instead the answer is
44 bytes (`safctf{8-4-4-4-12}` UUID) or 40 bytes (`safctf{32hex}` receipt) and
the remaining bytes are padding, the earlier test is invalid for those models.
This script solves for the keystream under each model with the strong
constraint sets, for every period and every fragment permutation.
"""
import base64, itertools, sys

IDS = {0: "PZRA3C5MF2WARTI", 1: "6CYYWT3ECKT45IY", 2: "B256MK23FAQL2VY",
       3: "PVC46ZEQQHTN7UI", 4: "FJQLJ6KV2NM66HY", 5: "BZDPUAPZ44P4WHQ",
       6: "4N6YDDXKVZSNSDI", 7: "UORLITSJBNLJVUI"}
takes = [base64.b32decode(IDS[i] + "=") for i in range(8)]

HEX = set(b"0123456789abcdef")
FREE = set(range(256))
MASK256 = (1 << 256) - 1


def rotl(m, c):
    return ((m << c) | (m >> (256 - c))) & MASK256


def model(kind):
    """Return the allowed set per message position."""
    s = []
    for p in range(72):
        if kind == "uuid44":      # safctf{8-4-4-4-12} then 28 free bytes
            if p < 7:
                s.append({b"safctf{"[p]})
            elif p <= 42:
                s.append(HEX | ({ord('-')} if p in (15, 20, 25, 30) else set()))
            elif p == 43:
                s.append({ord('}')})
            else:
                s.append(FREE)
        elif kind == "hex40":     # safctf{32hex} receipt then 32 free bytes
            if p < 7:
                s.append({b"safctf{"[p]})
            elif p <= 38:
                s.append(HEX)
            elif p == 39:
                s.append({ord('}')})
            else:
                s.append(FREE)
        elif kind == "hex64":     # safctf{64hex}
            if p < 7:
                s.append({b"safctf{"[p]})
            elif p < 71:
                s.append(HEX)
            else:
                s.append({ord('}')})
        elif kind == "uuid44mix":  # uuid at any of the 9 fragment boundaries
            s.append(FREE)
        else:
            raise ValueError(kind)
    return s


def masks_for(sets):
    m = []
    for st in sets:
        v = 0
        for b in st:
            v |= 1 << b
        m.append(v)
    return m


def solve(msg, msk, L):
    """Return (feasible, all_constrained_determined, plaintext|None)."""
    masks = [MASK256] * L
    constrained = [False] * L
    for p, c in enumerate(msg):
        masks[p % L] &= rotl(msk[p], c)
        if masks[p % L] == 0:
            return False, False, None
        if len(msk[p].to_bytes(0, "big")) and bin(msk[p]).count("1") < 256:
            constrained[p % L] = True
    out = bytearray(msg)
    determinate = True
    for r in range(L):
        if constrained[r] and bin(masks[r]).count("1") != 1:
            determinate = False
        if bin(masks[r]).count("1") == 1:
            k = masks[r].bit_length() - 1
            for p in range(r, 72, L):
                out[p] = msg[p] ^ k
    return True, determinate, bytes(out)


def run(order, kind, label):
    msg = b"".join(takes[i] for i in order)
    sets = model(kind)
    msk = masks_for(sets)
    hits = 0
    for L in range(1, 72):
        feas, det, pt = solve(msg, msk, L)
        if feas and det:
            hits += 1
            print(f"* {label} order={order} L={L}: {pt!r}")
    return hits


if __name__ == "__main__":
    total = 0
    for kind in ("uuid44", "hex40"):
        for order in (list(range(8)), [3, 1, 7, 6, 2, 5, 4, 0]):
            total += run(order, kind, kind)
    print("period/permutation hits:", total)
    # exhaustive permutations for the two models (identity offsets, all perms)
    print("=== all 8! permutations ===")
    cnt = 0
    for perm in itertools.permutations(range(8)):
        for kind in ("uuid44", "hex40"):
            sets = model(kind)
            msk = masks_for(sets)
            msg = b"".join(takes[i] for i in perm)
            for L in range(1, 72):
                feas, det, pt = solve(msg, msk, L)
                if feas and det:
                    cnt += 1
                    print("*", kind, perm, L, pt)
                    if cnt > 20:
                        sys.exit(0)
    print("perm hits:", cnt)
