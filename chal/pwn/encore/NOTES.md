# Encore — PWN (500)

- Target: `http://54.72.82.22:8200` (Werkzeug/Flask desk; binary served at `/download`)
- Binary: `/download` on the desk — sha256 `9a51e70f7c101942bf55640fb802168518e8e70e80a32b7eafc17b1061d23c48`
- Flag: `safctf{a6aca5b356ad7824a01d0a767b2cd998}`

## Mitigations

| | |
|---|---|
| Arch | amd64-64-little |
| PIE | **No** (base `0x400000`) |
| Canary | **None** |
| NX | **Disabled** (GNU_STACK missing) — stack executable |
| RELRO | Partial |
| SHSTK/IBT | property bits set (CET-compiled, `endbr64`) but not enforced |

Classic unhardened binary. No remote `nc` service is needed: the binary itself
tells the player to submit answers on the web interface, so all three answers
are POSTed to the desk.

## The binary

Three sequential stages, each verifying input; failure calls `exit(1)`.

**Stage 1 — `stage1_reverse_engineering`**: builds a 14-byte blob on the stack and
XORs each byte with `0x42`, then `strcmp`s against input.
Decoded key: **`R3v3rs3_M4st3r`**.

**Stage 2 — `stage2_cryptography`**: `vigenere_decrypt(cipher, "ENCORE")` then
`caesar13_decrypt` (ROT13), compared to input. Cipher is the marquee string
`Fvtsjcfw_1h_Q0a3iwua`. Decrypts to **`Overflow_1s_P0w3rful`**.

**Stage 3 — `stage3_exploitation` (the bug)**: `gets(rbp-0x40)` into a 64-byte
buffer — unbounded stack overflow, no canary, no PIE. Win function
`print_token` @ `0x40197b` prints the static token
`STAGE3_TOKEN = "3nc0r3_pwn3d_2025"` (`.rodata` @ `0x402010`) and `exit`s.

## Exploit chain

ret2win: `payload = b"A"*0x40 + b"B"*8 + p64(print_token)`.
Offset = 0x40 buffer + 8 saved RBP = 72 bytes, then the return address.
`print_token` prints the Stage 3 token.

## Web submission (`/submit/stageN`, session cookie required)

1. `stage1` = `R3v3rs3_M4st3r`
2. `stage2` = `Overflow_1s_P0w3rful`
3. `stage3` = `3nc0r3_pwn3d_2025` → returns the flag.

Requests must share the Flask session cookie (`GET /` first); otherwise the desk
replies `Please complete Stage N first!`.

`solve.py` runs the binary locally to obtain the token via the exploit, then
performs the three web submissions and prints the flag.
