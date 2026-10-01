#!/usr/bin/env python3
"""Parallel Lines (CRYPTO, 500 pts) - Safaricom CTF.

Target: http://54.72.82.22:8430

Attack: keystream reuse across two "parallel" exports.
  * lookbook.zip contains memo.txt (known plaintext, 153 B, 71 readable
    chars + '.' filler), export-a.bin (153 B), export-b.bin (64 B) and
    spool.json which carries an 8-byte nonce and `spool_order`, a
    permutation of 0..152 applied to export-a's bytes.
  * Un-shuffle export-a with spool_order (out[spool_order[i]] = a[i]).
  * XOR the un-shuffled A with the memo => recovered keystream.
  * XOR export-b with the same keystream => "Collection receipt: <token>".
  * POST the receipt token to /submit; the service answers with the flag.

Stdlib only.  Usage:  python3 solve.py [target]
"""
import io
import json
import sys
import urllib.request
import zipfile


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def unshuffle(data, order):
    out = bytearray(len(data))
    for i, pos in enumerate(order):
        out[pos] = data[i]
    return bytes(out)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8430"

    zf = zipfile.ZipFile(io.BytesIO(fetch(target + "/downloads/lookbook.zip")))
    memo = zf.read("memo.txt")
    a = zf.read("export-a.bin")
    b = zf.read("export-b.bin")
    spool = json.loads(zf.read("spool.json"))

    order = spool["spool_order"]
    a_fixed = unshuffle(a, order)

    keystream = bytes(x ^ y for x, y in zip(a_fixed, memo))
    receipt = bytes(x ^ y for x, y in zip(b, keystream[: len(b)])).decode()
    token = receipt.split(": ", 1)[1].strip()

    req = urllib.request.Request(
        target + "/submit",
        data=json.dumps({"answer": token}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        print(json.loads(r.read())["message"])


if __name__ == "__main__":
    main()
