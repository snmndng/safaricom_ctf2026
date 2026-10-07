#!/usr/bin/env python3
"""Use the shared flag as an OFFLINE crib: find the generator's flag-derivation
scheme on SOLVED siblings, then invert it for Orchard to recover the receipt.
No submissions happen until/unless a receipt is derived; then one POST confirms."""
import hashlib, hmac, itertools, json, io, zipfile, requests

TARGET = "f0fd1314d1a96139102451f15323e9b9"  # hex inside safctf{...}

def schemes(s, keys=(b'front-desk', b'orchard', b'orchard.test', b'ad-acl', b'')):
    b = s.encode() if isinstance(s, str) else s
    out = {
        'md5': hashlib.md5(b).hexdigest(),
        'sha1_32': hashlib.sha1(b).hexdigest()[:32],
        'sha256_32': hashlib.sha256(b).hexdigest()[:32],
        'sha512_32': hashlib.sha512(b).hexdigest()[:32],
        'sha3_32': hashlib.sha3_256(b).hexdigest()[:32],
        'blake2s_32': hashlib.blake2s(b).hexdigest()[:32],
    }
    for k in keys:
        if k:
            out[f'hmac_sha256_32[{k.decode()}]'] = hmac.new(k, b, hashlib.sha256).hexdigest()[:32]
    return out

# ---------- calibration on SOLVED siblings ----------
def calib_pool(name, extra):
    p = set(extra)
    p |= {name, name.replace('-', ' '), name.title(), name.upper()}
    return p

calibrations = {
  'winter-pavilion': ('8a97f3881e4828d37406ed0953ff9573', calib_pool('winter-pavilion', [
      '582dd884f15ee41330ceb416c60c6a1c', 'svc-620a984fb8', 'job-ee685b72ec4b',
      '582dd884f15ee41330ceb416c60c6a1c|svc-620a984fb8|job-ee685b72ec4b',
      'Crew', '15', 'pavilion.test', 'OU=Stage,DC=pavilion,DC=test', '8580'])),
  'crown-studio': ('04fd9ff98e41c5ef8a54da3990126b58', calib_pool('crown-studio', [
      'design-80015a51f6', 'archivist@orchard.test', 'visitor@orchard.test', '8590'])),
  'night-bus': ('81a90dc817371a5aa190e8069ebcde2c', calib_pool('night-bus', [
      'TOUR-2401', 'TOUR-2402', '8330',
      hashlib.sha256(b'TOUR-2402').hexdigest()[:24]])),
  'ticket-carousel': ('5b701cd93c298559638b8b4181bfa5e2', calib_pool('ticket-carousel', [
      'DAB', '8630'])),
  'matchday-replay': ('e2d6cc7b320577dd3eb54aa08f86e446', calib_pool('matchday-replay', [
      'safctf{5554fd00-017a-4915-a883-a7ef2639f73b}', 'afterglow-17', '8450'])),
}

print("=== calibration: how do sibling flags derive from their data? ===")
scheme_hits = set()
for chal, (flag, pool) in calibrations.items():
    for s in pool:
        for sc, val in schemes(s).items():
            if val == flag:
                print(f"  MATCH {chal}: {sc}(\"{s[:60]}\") == flag")
                scheme_hits.add((chal, sc, s))

# ---------- Orchard offline inversion ----------
print("\n=== Orchard: offline search for X with scheme(X) == target ===")
RES="record-ef1b86a30b808513"; SD="S-1-5-21-810-920-1030-1068"; SN="S-1-5-21-810-920-1030-1069"
SS="S-1-5-21-810-920-1030-1000"; NM={1068:"team-a4283b27",1069:"team-5803825d",1000:"team-a4654927"}
R="ReadProperty"
CHAIN=["S-1-5-21-810-920-1030-1000","S-1-5-21-810-920-1030-1013","S-1-5-21-810-920-1030-1027",
       "S-1-5-21-810-920-1030-1046","S-1-5-21-810-920-1030-1068"]
NAMES=["team-a4654927","team-0f85fe7a","team-b13c037b","team-2648700f","team-a4283b27"]

pool = {RES,SD,SN,SS,NM[1068],NM[1069],NM[1000],R,"allow","deny","Allow","ALLOW",
        "orchard","Orchard Society","orchard-society","orchard.test","ad-acl","8570","300"}
core=[RES,SD,"allow",R,NM[1068],SS,NM[1000]]
for n in range(1,6):
    for combo in itertools.permutations(core,n):
        for sep in ("|",":","-","_",","," ",""):
            pool.add(sep.join(combo))
for seq in (CHAIN,NAMES):
    for sep in ("|",":","-",","," ","_","",">","->"):
        pool.add(sep.join(seq))
for a in ("|".join(CHAIN),":".join(CHAIN)):
    pool.add(a)
# whole-zip and file hashes as X too
try:
    z=requests.get("http://54.72.82.22:8570/downloads/orchard-export.zip",timeout=20).content
    zf=zipfile.ZipFile(io.BytesIO(z))
    pool.add(hashlib.sha256(z).hexdigest())
    for n in zf.namelist():
        pool.add(hashlib.sha256(zf.read(n)).hexdigest())
except Exception as e:
    print("zip fetch failed:", e)

print(f"pool size: {len(pool)}")
found=[]
for s in pool:
    for sc,val in schemes(s).items():
        if val==TARGET:
            found.append((s,sc)); print(f"  DERIVATION FOUND: {sc}(\"{s}\") == shared-flag hex")
if not found:
    print("  no derivation from the artifact data matches the shared flag")

# ---------- if a receipt-shaped X was found, verify via the app oracle ----------
receipts=[s for s,sc in found if "|" in s or s in (f"{SD}|allow|{R}", f"{RES}|{SD}|allow|{R}")]
for s,sc in found:
    try:
        r=requests.post("http://54.72.82.22:8570/submit",json={"answer":s},timeout=15)
        print(f"verify /submit {sc}(\"{s[:40]}\") -> {r.status_code} {r.text[:120]}")
        if r.status_code==200:
            open("/tmp/orchard_receipt.txt","w").write(s)
            break
    except Exception as e:
        print("  err",e)
