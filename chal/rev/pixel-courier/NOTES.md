# Pixel Courier — REVERSE (150 pts)

**FLAG:** `safctf{e7802274-4b04-488a-9319-39ca86e83c9f}`

## Target
- Page: http://54.72.82.22:8510/ (title "Pixel Courier", the only download link is `receipt`).
- Artifact: `GET /downloads/receipt` → 14520 bytes.
  - `file`: ELF 64-bit LSB executable, x86-64, dynamically linked,
    interpreter `/lib64/ld-linux-x86-64.so.2`, **stripped**, GCC 14.2.0.
  - sha256 `846fd968cdf2ca9493bbd29e678217c6c56213ac059cf299ebc16963830bb50d`
  - size 14520 bytes (not committed — `.gitignore` blocks binaries; fetch with solve.py).

## Note on the hint
The triage hint suggested "image/PNG-based flag encoding". That was **wrong** for this
challenge — the downloadable artifact is a native ELF, not an image. No PNG/stego work was
needed. (The name/theme is just flavor: "Pixel Courier".)

## Reverse engineering
Entry `_start` @ `0x401080` passes `main` @ `0x4011e4`. Only two libc calls matter
(`fgets`, `strcspn`, `strlen`, `putchar`, `puts`). Two user functions:
- `main` @ `0x4011e4` — the checker.
- render `0x401166` — prints the flag when the check passes.

### Checker (`main`)
1. `puts` prompt, `fgets(buf, 0x80, stdin)`, strip `\n` via `strcspn` delimiter at `0x402011`.
2. `strlen(buf)` must equal `0x18` = **24**.
3. Two 24-byte tables built on the stack via `movabs` immediates:
   - `T1` (`rbp-0xb0`) — a **permutation of 0..23**, indexes into the input.
   - `T2` (`rbp-0xd0`) — target byte values.
4. For `i` in `0..23`:
   ```
   out  = ((13*i + 0x5b) ^ buf[T1[i]]) + i     # compared as an 8-bit (dl) value
   fail if low8(out) != T2[i]
   ```

### Inverting the check (all mod 256)
```
(P ^ buf[T1[i]]) == (T2[i] - i)     with P = (13*i + 0x5b) & 0xff
=>  buf[T1[i]] = P ^ ((T2[i] - i) & 0xff)
```
Accepted input: `DWT8V52N2HLTUQE6CPGBQMJJ` (24 chars).

### Flag printer (`0x401166`)
When the check passes, `main` calls `0x401166` with `rdi = buf`:
```
key = 44-byte blob @ 0x404060 (.data)
for i in 0..43: putchar(key[i] ^ buf[i % 24])
```
The 44 printed bytes are exactly the flag (44 chars). Extracting `key` from `.data`
and XOR-ing against the repeating 24-byte input yields:
`safctf{e7802274-4b04-488a-9319-39ca86e83c9f}`

## Verification
Ran the real binary:
```
$ echo "DWT8V52N2HLTUQE6CPGBQMJJ" | ./receipt
Parcel desk
safctf{e7802274-4b04-488a-9319-39ca86e83c9f}     # exit 0
$ echo "wrongtest" | ./receipt
Parcel desk                                        # exit 1
```

## Tools used
`curl`, `readelf`, `objdump -d -M intel`, `strings`, Python 3 (stdlib only) for the solve.

## Files
- `solve.py` — fetches `/downloads/receipt`, parses T1/T2/key straight from the ELF
  (with recorded-constant fallback), and prints the flag.
- `receipt.bin` / `receipt` — fetched artifact (untracked; binary).
