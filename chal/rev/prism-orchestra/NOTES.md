# Prism Orchestra — REVERSE, 750 pts

**Flag:** `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}`

## Material

- Server: `http://54.72.82.22:8530` (Werkzeug/Flask), page offers two downloads:
  - `/downloads/receipt` — stripped Linux x86-64 ELF, no extension
    sha256 `6549b17ee5a07af02702ca7c6c1e54408054007c2a37548d7b12f8029c227007`
  - `/downloads/score.bin` — 540-byte bytecode blob
    sha256 `16be4ea7319b9c385900cbe97a718ac2f8e00d40addf3ece4ee072dc8d710892`
- Neither binary is committed (ELF kept out of git via `.gitignore`; `*.bin`
  already ignored). `solve.py` embeds `score.bin` so it runs standalone.

## Structure

`receipt` is 1.5 KB and does all of this in `main` (0x401224):

1. `fgets` 24 chars from stdin, newline stripped, `strlen == 0x18` required.
   That 24-byte buffer is the VM's register file (mem[0..23]).
2. Opens `/app/downloads/score.bin`; loop reads 3 bytes per instruction —
   `opcode, a, b` (`a` validated `0..0x17`, `b` `0..255`) — and applies:
   - `1`: `mem[a] ^= b`
   - `2`: `mem[a] += b` (mod 256)
   - `3`: `mem[a] = rol8(mem[a], (b % 7) + 1)`  (the `*0x92492493` + `% 7` code
     is just `b % 7`; the shift pair is a byte rotate)
   - `4`: `swap(mem[a], mem[b % 24])`  (`b - 24*int(b/24)`)
   - anything else → return code 3 (error)
3. `memcmp(mem, TARGET, 24)` against
   `49 2e 0d 7f df 2a 96 8d | 77 f1 e1 6e ab f1 37 a3 | 96 ab 62 07 85 5d eb 6d`
   (three `movabs` at 0x40122f/0x401239/0x401251).
4. On success calls 0x4011a6, which prints
   `TABLE[i] ^ mem[i % 24]` for a 44-byte table at `.data:0x404080`
   (`37 25 36 36 ... 04 60 2d`). That XOR stream is the flag.

`score.bin` = 180 instructions, opcodes {1:53, 4:52, 3:39, 2:36}, `a` in 0..23.

## Technique

No solver/emulator needed — every opcode is invertible and the program is a
straight-line sequence, so the input is recovered by walking the instruction
list **backwards** and applying the inverse of each op to `TARGET`:

    ^= b            -> ^= b            (self-inverse)
    += b            -> -= b
    rol8(x, k)      -> ror8(x, k)
    swap(a, b%24)   -> swap(a, b%24)   (self-inverse)

The resulting 24 bytes (`DDPU5WDMVRKQ2APHL7WPM78W`) are the required input;
XORing the `.data` table with `input[i % 24]` gives the flag.

## Verification

- `solve.py` forward-runs the VM on the recovered input and asserts it lands on
  `TARGET` (self-check).
- Ran the real ELF with its `/app/downloads/score.bin` path patched to a local
  copy: `printf 'DDPU5WDMVRKQ2APHL7WPM78W\n' | ./receipt_patched`
  → `Sound desk` then `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}`, rc=0.
- `POST /submit {"answer": ...}` returns `{"ok": false}` — the deployed submit
  endpoint rejects everything (likely decoy/broken, cf. the "Mr Beast
  Configuration" box). The binary's own output is the authoritative check.

## Reproduce

```
python3 solve.py
# input : DDPU5WDMVRKQ2APHL7WPM78W
# FLAG  : safctf{406279bd-3201-499f-9a4a-f14e8918eb37}
```
