#!/usr/bin/env python3
"""Deeper analysis of Long Exposure artifacts."""
import base64
import hashlib

# Load ciphertext (72 bytes in seq order)
ciphertext = bytes.fromhex("7e620d8bac2eac08cdf0b18b4f6412a7cea30ebbe62b5b2820bd577d45cf649081e6dfd12a60b4f955d359ef1f0e46fa01f9e71fcb1ee37d818eeaae64d90da3a2b44e490b569ad1")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Length: {len(ciphertext)}")

# QRY IDs
qry_ids = {
    0: "PZRA3C5MF2WARTI",
    1: "6CYYWT3ECKT45IY",
    2: "B256MK23FAQL2VY",
    3: "PVC46ZEQQHTN7UI",
    4: "FJQLJ6KV2NM66HY",
    5: "BZDPUAPZ44P4WHQ",
    6: "4N6YDDXKVZSNSDI",
    7: "UORLITSJBNLJVUI",
}

# Arrival order: 3, 1, 7, 6, 2, 5, 4, 0
arrival_order = [3, 1, 7, 6, 2, 5, 4, 0]

# 1. Check if arrival order matters - reassemble in arrival order
print("\n=== Arrival order ciphertext ===")
arrival_ciphertext = b""
for seq in arrival_order:
    name = qry_ids[seq]
    decoded = base64.b32decode(name + "=")
    arrival_ciphertext += decoded
    print(f"  seq {seq}: {decoded.hex()}")

print(f"Arrival ciphertext: {arrival_ciphertext.hex()}")

# 2. Check if the QRY IDs themselves contain the seed
print("\n=== QRY ID analysis ===")
all_ids = "".join(qry_ids[s] for s in sorted(qry_ids))
print(f"All IDs concatenated: {all_ids}")
print(f"Length: {len(all_ids)} chars")

# Hash of all IDs
for h in [hashlib.sha256, hashlib.md5, hashlib.sha1]:
    digest = h(all_ids.encode()).digest()
    print(f"{h.__name__}: {digest.hex()[:14]}...")

# Hash of IDs in arrival order
arrival_ids = "".join(qry_ids[s] for s in arrival_order)
print(f"\nArrival order IDs: {arrival_ids}")
for h in [hashlib.sha256, hashlib.md5, hashlib.sha1]:
    digest = h(arrival_ids.encode()).digest()
    print(f"{h.__name__}: {digest.hex()[:14]}...")

# 3. Check individual QRY ID hashes as seeds
print("\n=== Individual QRY ID hashes ===")
for seq in sorted(qry_ids):
    name = qry_ids[seq]
    for h in [hashlib.sha256, hashlib.md5, hashlib.sha1]:
        digest = h(name.encode()).digest()
        # Check if prefix matches target
        if digest[:7] == bytes.fromhex("0d036be8d848d7"):
            print(f"  *** MATCH seq {seq} {h.__name__}: {digest.hex()}")
        if h == hashlib.sha256:
            print(f"  seq {seq} sha256: {digest.hex()[:14]}...")

# 4. Try arrival order ciphertext with crib
print("\n=== Arrival order crib test ===")
crib = b"safctf{"
target = bytes.fromhex("0d036be8d848d7")
for i, seq in enumerate(arrival_order):
    name = qry_ids[seq]
    decoded = base64.b32decode(name + "=")
    # This fragment is at position i*9 in arrival ciphertext
    expected_ks = bytes(a ^ b for a, b in zip(decoded[:min(7, len(decoded))], crib[i*9:][:min(7, len(decoded))]))
    print(f"  Arrival pos {i} (seq {seq}): expected ks = {expected_ks.hex()}")

# 5. Check if ciphertext in arrival order XOR seq order gives something
print("\n=== Seq vs Arrival XOR ===")
seq_ct = ciphertext
arr_ct = arrival_ciphertext
xor_result = bytes(a ^ b for a, b in zip(seq_ct, arr_ct))
print(f"Seq XOR Arrival: {xor_result.hex()}")

# 6. Check NOI packets - load and analyze
print("\n=== NOI packet analysis ===")
with open('/home/nomad/safaricom_ctf/work/long-exposure/uplink.pcap', 'rb') as f:
    raw = f.read()

end = "<"
off = 24
noi_data = b""
while off + 16 <= len(raw):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(end + "IIII", raw[off:off+16])
    off += 16
    pkt = raw[off:off+incl_len]
    off += incl_len
    if pkt[:3] == b"NOI":
        noi_data += pkt[3:]

print(f"Total NOI data: {len(noi_data)} bytes")
print(f"First 100: {noi_data[:100].hex()}")

# Check if NOI data contains the required keystream prefix
target = bytes.fromhex("0d036be8d848d7")
# Search for target in NOI data
for i in range(len(noi_data) - 7):
    if noi_data[i:i+7] == target:
        print(f"  *** FOUND target at NOI offset {i}")

# Also check if NOI data XOR ciphertext gives plaintext
for offset in [0, 9, 18, 27, 36, 45, 54, 63]:
    if offset + 72 <= len(noi_data):
        ks = noi_data[offset:offset+72]
        pt = bytes(a ^ b for a, b in zip(ciphertext, ks))
        if pt.startswith(b"safctf{") or all(32 <= b < 127 for b in pt):
            print(f"  NOI offset {offset}: PT = {pt}")

# 7. Check process.core
print("\n=== process.core analysis ===")
with open('/home/nomad/safaricom_ctf/work/long-exposure/process.core', 'rb') as f:
    core = f.read()
print(f"Size: {len(core)} bytes")
print(f"First 100: {core[:100].hex()}")

# Search for target in core
for i in range(len(core) - 7):
    if core[i:i+7] == target:
        print(f"  *** FOUND target in core at offset {i}")

# Check core as keystream at various offsets
for offset in range(0, min(100, len(core) - 72), 9):
    ks = core[offset:offset+72]
    pt = bytes(a ^ b for a, b in zip(ciphertext, ks))
    if pt.startswith(b"safctf{"):
        print(f"  Core offset {offset}: PT = {pt}")

# 8. Check the timestamp in PCAP
print("\n=== PCAP timestamps ===")
with open('/home/nomad/safaricom_ctf/work/long-exposure/uplink.pcap', 'rb') as f:
    raw = f.read()

end = "<"
off = 24
timestamps = []
while off + 16 <= len(raw):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(end + "IIII", raw[off:off+16])
    timestamps.append(ts_sec)
    off += 16 + incl_len

print(f"Timestamps: {timestamps[:5]}... (total {len(timestamps)})")
print(f"First: {timestamps[0]} = {timestamps[0]}")
print(f"Deltas: {[timestamps[i+1]-timestamps[i] for i in range(min(10, len(timestamps)-1))]}")

# 9. The "blue hour" - could it be a specific time?
# Blue hour is around sunset/sunrise. Let's check if timestamp encodes something.
# 1800000000 = Thu Jan 15 2027 17:20:00 GMT+0000
# But that's in the future. Maybe it's a different epoch?

import struct