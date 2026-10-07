#!/usr/bin/env python3
"""Analyze Long Exposure uplink.pcap in detail."""
import struct
import base64

with open('/home/nomad/safaricom_ctf/work/long-exposure/uplink.pcap', 'rb') as f:
    raw = f.read()

print(f"PCAP size: {len(raw)} bytes")
print(f"Magic: {raw[:4].hex()}")

end = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
print(f"Endian: {end}")

off = 24
noi_payloads = []
qry_packets = {}

while off + 16 <= len(raw):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(end + "IIII", raw[off:off+16])
    off += 16
    pkt = raw[off:off+incl_len]
    off += incl_len
    
    if pkt[:3] == b"NOI":
        noi_payloads.append(pkt[3:])
    elif pkt[:3] == b"QRY":
        seq = struct.unpack(">H", pkt[3:5])[0]
        name = pkt[5:].decode("latin1")
        qry_packets[seq] = name

print(f"\nNOI packets: {len(noi_payloads)}")
print(f"QRY packets: {len(qry_packets)}")

print("\nNOI payload lengths:")
for i, p in enumerate(noi_payloads):
    print(f"  NOI[{i}]: {len(p)} bytes")
    if i < 3:
        print(f"    {p.hex()}")

print("\nQRY packets (seq order):")
for seq in sorted(qry_packets):
    name = qry_packets[seq]
    b32_part = name.split(".")[0]
    try:
        decoded = base64.b32decode(b32_part + "=")
        print(f"  seq {seq}: {name} -> {decoded.hex()} ({len(decoded)} bytes)")
    except Exception as e:
        print(f"  seq {seq}: {name} -> ERROR: {e}")

print("\nQRY packets (arrival order):")
# Sort by packet offset in file (which is arrival order)
# We need to track arrival order from the parsing above
# Let me re-parse with arrival index

off = 24
arrival_idx = 0
arrival_order = []
while off + 16 <= len(raw):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(end + "IIII", raw[off:off+16])
    off += 16
    pkt = raw[off:off+incl_len]
    off += incl_len
    
    if pkt[:3] == b"QRY":
        seq = struct.unpack(">H", pkt[3:5])[0]
        arrival_order.append((arrival_idx, seq))
        arrival_idx += 1

print("Arrival order (idx, seq):")
for idx, seq in arrival_order:
    print(f"  {idx}: seq {seq}")

# Also check the full decoded takes in seq order
print("\nDecoded takes in seq order (9 bytes each):")
full_ciphertext = b""
for seq in sorted(qry_packets):
    name = qry_packets[seq]
    b32_part = name.split(".")[0]
    decoded = base64.b32decode(b32_part + "=")
    full_ciphertext += decoded
    print(f"  seq {seq}: {decoded.hex()}")

print(f"\nFull ciphertext (72 bytes): {full_ciphertext.hex()}")
print(f"Length: {len(full_ciphertext)}")

# Check if it starts with safctf{ when XORed with something
crib = b"safctf{"
target = bytes(a ^ b for a, b in zip(full_ciphertext[:7], crib))
print(f"\nRequired sha256(seed)[0:7] = {target.hex()}")
print(f"  = {list(target)}")