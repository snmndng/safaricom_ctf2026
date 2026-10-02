#!/usr/bin/env python3
"""
Long Exposure (FORENSICS, 750 pts) - solve / best-attempt script.

Target desk : http://54.72.82.22:8470
Materials   : GET /downloads/field-kit.zip
              (process.core 32768 B, uplink.pcap 9282 B, modules.map 37 B,
               field-note.txt 119 B -- sha256s recorded in NOTES.md)
Submit      : POST /submit {"answer": "<answer>"}  ->  {"ok":true,"message":"safctf{...}"}

What the artefacts contain (reverse engineered, see NOTES.md for the full log):
  uplink.pcap is LINKTYPE_USER0 (DLT 147) -- raw payloads, no link layer.
  Two ASCII-tagged record types:
    NOI : b"NOI" + 40 random bytes                         x150  (decoy, uniform)
    QRY : b"QRY" + seq(2,big-endian) + 30-byte name        x8
          name = base32(<15 chars>) + ".img.field.test"
          -> base32decode gives 9 bytes per take; 8 takes = 72 bytes ("takes")
  process.core is 32768 bytes of os.urandom-quality noise (chi2 252 / df 255,
  no autocorrelation, no ASCII strings) -- a decoy "warm buffer".
  field-note.txt / modules.map carry the prose smell of the seed but contain no
  obvious card id.

Hypothesised cipher (matches the solved sibling chal/forensics/matchday-replay):
  P[pos] = C[pos] XOR K[pos % L],  K = sha256(seed),  L = len(seed)
  where C = the 72 decoded take bytes in seq order and P starts "safctf{".
  i.e. the required sha256(seed) prefix is C[0:7] XOR b"safctf{".
  This script applies that crib as a fast filter over a candidate seed list.

Status: the flag was NOT recovered.  Run for the crib filter / candidates.
"""
import base64
import hashlib
import io
import json
import os
import re
import struct
import sys
import urllib.request
import zipfile

BASE = "http://54.72.82.22:8470"
ZIP_URL = BASE + "/downloads/field-kit.zip"

# QRY seq -> base32 15-char id (from uplink.pcap, seq order 0..7)
QRY_IDS = {0: "PZRA3C5MF2WARTI", 1: "6CYYWT3ECKT45IY", 2: "B256MK23FAQL2VY",
           3: "PVC46ZEQQHTN7UI", 4: "FJQLJ6KV2NM66HY", 5: "BZDPUAPZ44P4WHQ",
           6: "4N6YDDXKVZSNSDI", 7: "UORLITSJBNLJVUI"}
CRIB = b"safctf{"


def fetch_zip():
    with urllib.request.urlopen(ZIP_URL, timeout=30) as r:
        return r.read()


def parse_pcap(raw):
    """Return (noi_payloads, {seq: name}) from the custom USER0 capture."""
    end = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    off, noi, qry = 24, [], {}
    while off + 16 <= len(raw):
        _ts, _tus, incl, _orig = struct.unpack(end + "IIII", raw[off:off + 16])
        off += 16
        pkt = raw[off:off + incl]
        off += incl
        if pkt[:3] == b"NOI":
            noi.append(pkt[3:])
        elif pkt[:3] == b"QRY":
            qry[struct.unpack(">H", pkt[3:5])[0]] = pkt[5:].decode("latin1")
    return noi, qry


def decoded_takes(qry):
    """72 ciphertext bytes, fragments in seq order."""
    out = b""
    for s in sorted(qry):
        name = qry[s].split(".")[0]
        out += base64.b32decode(name + "=")
    return out


def keystream_plaintext(C, seed):
    """matchday-replay rule: P[pos] = C[pos] XOR sha256(seed)[pos % len(seed)]."""
    sb = seed.encode() if isinstance(seed, str) else seed
    if not 0 < len(sb) <= 32:
        return None
    K = hashlib.sha256(sb).digest()
    L = len(sb)
    return bytes(c ^ K[i % L] for i, c in enumerate(C))


def candidate_seeds():
    """Themed strings + every substring/word-combo of the text artefacts."""
    page = ("LONG EXPOSURE PHOTOGRAPHY An ordinary day A different story "
            "Some moments belong to the blue hour Collection desk Materials for "
            "your visit are available below From the room Keep your collection "
            "receipt when your visit is complete Open for the evening The camera "
            "spool retained a warm buffer after the blue-hour test Original and "
            "processed takes were exported together 00001000-00009000 rw-p "
            "studio-worker field-kit.zip uplink.pcap process.core modules.map "
            "field-note.txt")
    texts = [page, page.lower()]
    for fn in ("field-note.txt", "modules.map"):
        if os.path.exists(fn):
            t = open(fn).read()
            texts += [t, t.lower(),
                      re.sub(r"[^A-Za-z0-9]+", "-", t).strip("-"),
                      re.sub(r"[^A-Za-z0-9]+", "", t)]
    seen = set()
    for t in texts:
        n = len(t)
        for i in range(n):
            for L in range(1, min(48, n - i) + 1):
                seen.add(t[i:i + L])
    for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-_]+", " ".join(texts)):
        seen.add(w)
        for n in range(100):
            seen.add("%s-%02d" % (w, n))
            seen.add("%s%d" % (w, n))
    return seen


def main():
    try:
        zdata = fetch_zip()
        zf = zipfile.ZipFile(io.BytesIO(zdata))
        cap = zf.read("uplink.pcap")
        noi, qry = parse_pcap(cap)
        takes = decoded_takes(qry)
        print("[+] pcap: %d NOI, %d QRY; %d decoded take bytes" % (len(noi), len(qry), len(takes)))
    except Exception as e:                                    # offline fallback
        print("[!] download failed (%s); using embedded QRY ids" % e)
        takes = decoded_takes({s: QRY_IDS[s] + ".img" for s in QRY_IDS})

    # required sha256(seed) prefix from the "safctf{" crib
    target = bytes(a ^ b for a, b in zip(takes[:7], CRIB))
    print("[+] required sha256(seed)[0:7] = %s" % target.hex())

    wl = sys.argv[1] if len(sys.argv) > 1 else None
    seeds = candidate_seeds()
    if wl:
        seeds |= {l.strip() for l in open(wl, "rb").read().splitlines() if l.strip()}
    print("[+] %d candidate seeds" % len(seeds))

    for s in seeds:
        sb = s.encode() if isinstance(s, str) else s
        if not 0 < len(sb) <= 32:
            continue
        if hashlib.sha256(sb).digest()[:7] != target:
            continue
        P = keystream_plaintext(takes, sb)
        print("*** SEED MATCH seed=%r -> %r" % (sb, P))
        if P.startswith(CRIB):
            answer = P.rstrip(b"\x00").decode("latin1")
            print("[+] answer: %s" % answer)
            req = urllib.request.Request(BASE + "/submit",
                                         data=json.dumps({"answer": answer}).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                resp = json.loads(r.read().decode())
            print("[+] submit -> %s" % resp)
            if resp.get("ok"):
                print("FLAG: %s" % resp.get("message"))
            return 0
    print("[-] no seed matched the crib; flag not recovered (see NOTES.md)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
