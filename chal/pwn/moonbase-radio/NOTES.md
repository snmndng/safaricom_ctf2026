# Moonbase Radio — pwn (SOLVED)

- Desk page: `http://54.72.82.22:8620/` (themed SPACE RADIO)
- Binary: `http://54.72.82.22:8620/downloads/receipt` (raw ELF, no extension)
  - sha256 `2c45100895988a3b4aede7c6e2723970ff46d53351ad62104ef528b32b8ed606`
  - Local copy kept as `receipt` (binary extensions are gitignored — NOT committed)
- Remote service: `nc 54.72.82.22 8750`, banner is a bare `Moonbase Radio\n`
- Flag: `safctf{d8e20273d4d4cd65472f84b4316666eb}`

## Triage

`file receipt` -> ELF 64-bit LSB **PIE**, dynamically linked, **stripped**.
`checksec` -> Partial RELRO, **No canary**, NX enabled, PIE enabled.

The service prints only the banner and then calls `scanf("%u", &option)` in a loop
(no prompt). The four menu options map to the small main loop at `0x1275`:

| option | code | behaviour |
|--------|------|-----------|
| 1 | `0x12d6` | `p = malloc(0x40); memset(p,0,0x40); *(p+0x38)=0x124e; printf("channel=%p\n", *(p+0x38))` |
| 2 | `0x1329` | `if (p1) free(p1);` — **p1 is never nulled** |
| 3 | `0x1346` | `p2 = malloc(0x40); fread(p2, 1, 0x40, stdin)` |
| 4 | `0x137e` | `if (p1) { rdx = *(p1+0x38); call rdx; }` |

`0x124e` is the `puts("Silence between songs.")` stub stored as a function pointer.

## Bug — use-after-free / arbitrary call

`free` in option 2 leaves the pointer live, and option 3 hands back the *same*
0x40 tcache chunk (LIFO) and lets us `fread` 0x40 fully controlled bytes over it.
So `*(chunk+0x38)` becomes attacker-controlled, and option 4 calls it.

Also present (but not needed): a **dead win function at `0x1264`** (not referenced
anywhere), which does `fopen("/run/receipt","r"); fgets(buf,0xa0,f); puts(buf)`.
The binary's own name/URL is `receipt` and the path it opens is `/run/receipt`,
i.e. this is the intended ret2win — it prints the receipt file, which on the
server holds the flag.

## Exploit (see solve.py)

1. option 1 -> `printf("channel=%p", 0x124e)` leaks a PIE code pointer => `base = leak - 0x124e`.
2. option 2 -> `free(chunk)` (dangling pointer kept).
3. option 3 -> `malloc(0x40)` returns the freed chunk; `fread` writes
   `b"A"*0x38 + p64(base+0x1264)` over it (also clobbers tcache fd/key, harmless).
4. option 4 -> `call *(chunk+0x38)` == win -> prints `/run/receipt`.

The call needs no argument control (the win function takes none), so the
uncontrolled `rdi` at the call site does not matter. No libc leak / shell needed.

## Result

```
channel=0x56ce111b324e
FLAG: safctf{d8e20273d4d4cd65472f84b4316666eb}
```
Reproduced across runs (ASLR changes the leak, flag is stable).
