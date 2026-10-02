# Northern Lights — mobile, 200 pts

Target: http://54.72.82.22:8370 (desk app; `POST /submit {"answer": ...}`)

## Artifact
- `/downloads/device-export.zip`
- sha256 `dd8be3c21cee82782b306d66353b45d5634578f95918b13d64996c157fdf5d86`
- Contents: `Manifest.db` (iOS backup manifest, SQLite), `Keychain.plist`,
  `Library/Preferences/com.northern.lights.plist`, `Persistence.swift`,
  `d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607` (encrypted payload, 72 bytes).

## Scheme (documented in Persistence.swift)
```
key  = PBKDF2-SHA256(keychain.v_Data + UTF8(prefs.account), prefs.salt, prefs.iterations, 32)
blob = nonce[12] || AES.GCM.sealed || tag[16]
```

## Solving
- `Keychain.plist` has 13 items: **12 decoys** with `svce = preview`, and **one live**
  item with `svce = com.northern.lights`, `acct = 18485ad7d74ed05fad7e518b`.
- Prefs: `account = 18485ad7d74ed05fad7e518b` (matches the live item),
  `iterations = 24000`, `salt = 00078d28e71f06971f45d914a5bb3387`.
- Only the live keychain row's `v_Data` + that account derives a key that
  authenticates the GCM blob. Decoys fail the tag check.
- Blob splits: nonce = first 12 bytes, ciphertext+tag = remaining 60 bytes.

## Flag
- Intermediate (decrypted payload): `safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}`
- **Graded flag (from `/submit`): `safctf{3fd96340be891c629f7e3f3a42202743}`**

`solve.py` performs fetch -> parse -> decrypt -> submit end to end.
