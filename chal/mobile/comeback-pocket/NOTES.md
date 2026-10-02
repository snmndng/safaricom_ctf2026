# Comeback Pocket — mobile, 150

**Flag: `safctf{408e83b586354238e5a8e968a74b8b64}`** (graded answer from `/submit`;
the decrypted receipt `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}` is only the intermediate).

## Artifacts (kept out of git — binary extensions are gitignored)
| file | sha256 |
|---|---|
| `http://54.72.82.22:8360/downloads/pocket.ab` | `e6f127c9406fe64f282f969ef64180595a837558335dfcb4d7719b957e77635b` |
| `http://54.72.82.22:8360/downloads/Session.java` | `d0163b5bc4d903efb79f5215c771fe7c57dbf79ec3e94dee229527316cdac4d3` |

`Session.java` is the whole map:

```java
SecretKey load(String uid,String device,byte[] salt) {
 return PBKDF2WithHmacSHA256(uid+":"+device,salt,12000,256);
}
// pass.bin: 12-byte IV, AES/GCM ciphertext, 16-byte tag.
```

## Path
1. `pocket.ab` header: `ANDROID BACKUP\n5\n1\nnone\n` — version 5, compressed flag 1,
   no encryption. Payload after line 4 is a raw zlib stream → a tar of
   `apps/com.comeback.pocket/{db/accounts.db, sp/session.xml, f/pass.bin, _manifest}`.
   (`unzip` fails, as expected — parse the header + `zlib.decompress`.)
2. `sp/session.xml` gives the salt and KDF rounds:
   `<string name="s">67beb4eff155c1bff95be68fd8c2e4e0</string>` (16 bytes) and `rounds=12000`.
   `installation` = `member-2dea8614a9` ties to the active DB row.
3. `db/accounts.db` → `SELECT uid,device FROM accounts WHERE active=1` →
   `member-2dea8614a9` / `4e13eb4f120b8f4709ee20e57a597758`. The 30 other rows are decoys.
4. Key = PBKDF2-HMAC-SHA256(`uid:device`, salt, 12000, 32). Split `f/pass.bin` as
   IV(12) ‖ ct ‖ tag(16) and AES-GCM decrypt → receipt.
5. `POST /submit {"answer": receipt}` → graded flag.

## Run
```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```
