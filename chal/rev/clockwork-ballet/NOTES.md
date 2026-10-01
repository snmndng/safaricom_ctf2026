# Clockwork Ballet — REV 500

- Source: `http://54.72.82.22:8520/` ("Collection desk" -> `/downloads/receipt`)
- `receipt`: ELF 64-bit x86-64, stripped, dynamically linked
- sha256: `199bfdb14b66992412fade55d98531a2cec72eb099b1c93ace97e8aaa5a165a0`

## main() @ 0x4012bd
1. Builds 24-byte target on stack (6 dwords, little-endian):
   `af 01 49 42 | ec c4 11 a8 | 99 66 96 be | 04 ef b6 41 | 3c f1 8b c3 | 1e 1c 3a ba`
2. `puts("Wardrobe desk")`, `fgets` 0x80 into buf.
3. `strlen(buf) == 0x18` enforced (24 chars), newline stripped.
4. `for i in {0,2,4}: func_401204(buf + i*4)` → encrypts three 8-byte blocks in place.
5. `memcmp(buf, target, 24) == 0` → success.

## Transform — func_401204: classic TEA (32 rounds)
- `v0 = p[0]`, `v1 = p[1]`
- `sum += 0x9e3779b9` per round (encoded as `sub sum, 0x61c88647` = sum - (-delta)); 32 rounds (`i <= 0x1f`).
- Round body is textbook TEA:
  `v0 += ((v1<<4)+k0) ^ (v1+sum) ^ ((v1>>5)+k1)`
  `v1 += ((v0<<4)+k2) ^ (v0+sum) ^ ((v0>>5)+k3)`
- Key material in `.data` @ 0x404090: `k = [0xe23d414a, 0xfa100e27, 0x6ac599cc, 0x0c1d1a24]`

So verification is `TEA_encrypt(input) == target` → invert by TEA-decrypting each block.
Round-trip (decrypt then re-encrypt) asserted in solve.py.

Recovered 24-char passphrase: `HA323U86XL793TXB52BTK6WP`

## Win function — func_401186
Prints 44 bytes `mask[i] ^ passphrase[i % 24]`, mask @ 0x404060:
```
3b2055514733430f6b28035b5562396f5705776466026467716c0a02006d1555
6c7505080b636a2104067a29
```

## FLAG
`safctf{93d4bf6a-b750-4379-9038-c4921872c148}`

Validated by running the real binary: `printf 'HA323U86XL793TXB52BTK6WP\n' | ./receipt` → exit 0, prints the flag.

## Reproduce
```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```
