#!/usr/bin/env python3
"""
Photo Finish (API, 750 pts) — port 8350 @ 54.72.82.22

BEST ATTEMPT / RECON HARNESS.

Finding: :8350 does NOT serve the challenge app. It serves a stock, unregistered
Nessus Expert web UI (Server: NessusWWW, HTTPS-only). Every other challenge port
in the 8xxx range serves a Werkzeug/Flask app; 8350 is the lone outlier.

This script re-fingerprints the port, tests the virtual-host hypothesis (Host /
TLS SNI), probes the app-path surface, and — should a real Werkzeug JSON API ever
appear on the port — drives the board's standard desk flow:

    recover a receipt from the API  ->  POST /submit {"answer": "<receipt>"}
    (200 {"ok": true, "message": "safctf{...}"} == graded flag, 403 == wrong)

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import json
import socket
import ssl
import sys

import requests

requests.packages.urllib3.disable_warnings()

HOST = "54.72.82.22"
PORT = 8350
BASE = f"https://{HOST}:{PORT}"
PLAIN = f"http://{HOST}:{PORT}"


def banner():
    """Return the HTTP banner shape on the port (HTTP + HTTPS)."""
    out = {}
    try:
        r = requests.get(PLAIN + "/", timeout=8, verify=False)
        out["plain_http"] = (r.status_code, r.headers.get("Server", ""), r.text[:80])
    except Exception as e:
        out["plain_http"] = ("ERR", str(e)[:60], "")
    try:
        r = requests.get(BASE + "/", timeout=8, verify=False)
        out["https"] = (r.status_code, r.headers.get("Server", ""), r.text[:80])
    except Exception as e:
        out["https"] = ("ERR", str(e)[:60], "")
    return out


def vhost_probe(path="/"):
    """Host-header and TLS-SNI routing: is the real app virtual-hosted?"""
    names = ["photo-finish", "photofinish", "photo.finish", "api", "localhost",
             "finish", "photo", HOST, "chal-api-photo-finish"]
    results = {}
    for n in names:
        # plain Host header over TLS
        try:
            r = requests.get(BASE + path, timeout=6, verify=False, headers={"Host": n})
            results[f"Host:{n}"] = (r.status_code, r.headers.get("Server", ""))
        except Exception as e:
            results[f"Host:{n}"] = ("ERR", str(e)[:40])
        # TLS SNI
        try:
            ctx = ssl._create_unverified_context()
            raw = socket.create_connection((HOST, PORT), timeout=6)
            s = ctx.wrap_socket(raw, server_hostname=n)
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {n}\r\nConnection: close\r\n\r\n").encode())
            data = s.recv(200)
            s.close()
            hdr = data.decode("latin1", "replace").split("\r\n")
            results[f"SNI:{n}"] = (hdr[0] if hdr else "?", "NessusWWW" if b"nessus" in data.lower() else "?")
        except Exception as e:
            results[f"SNI:{n}"] = ("ERR", str(e)[:40])
    return results


def path_probe():
    """Does any non-Nessus JSON/API surface exist behind the port?"""
    paths = ["/", "/api", "/api/orders", "/api/photos", "/api/frames", "/api/status",
             "/orders", "/photos", "/frames", "/submit", "/health", "/robots.txt",
             "/docs", "/openapi.json", "/server/status", "/server/properties"]
    out = {}
    for p in paths:
        try:
            r = requests.get(BASE + p, timeout=6, verify=False)
            ct = r.headers.get("Content-Type", "")
            out[p] = (r.status_code, ct, r.text[:70].replace("\n", " "))
        except Exception as e:
            out[p] = ("ERR", str(e)[:40], "")
    return out


def desk_submit(candidate):
    """Board-standard desk flow: POST /submit {"answer": ...} -> graded flag."""
    try:
        r = requests.post(BASE + "/submit", json={"answer": candidate},
                          timeout=8, verify=False)
        if r.status_code == 200:
            msg = r.json().get("message", "")
            if msg.startswith("safctf{"):
                return f"FLAG {msg}"
            return f"200 non-flag {msg!r}"
        return f"{r.status_code} {r.text[:80]!r}"
    except Exception as e:
        return f"ERR {e}"


def main():
    print("=" * 68)
    print("Photo Finish — recon harness")
    print("=" * 68)

    b = banner()
    for k, v in b.items():
        print(f"[banner] {k:10} -> {v}")

    is_nessus = "nessus" in str(b).lower()
    print(f"\n[verdict] port serves {'Nessus (NOT the challenge app)' if is_nessus else 'an unknown app'}")

    print("\n[vhost] Host-header / TLS-SNI routing:")
    for k, v in vhost_probe().items():
        print(f"    {k:28} -> {v}")

    print("\n[paths] direct app-path probe:")
    for p, v in path_probe().items():
        print(f"    {p:20} -> {v}")

    if is_nessus:
        print("\n[!] :8350 is a stock Nessus Expert (HTTPS-only, unregistered:")
        print("    server/status code=503 download-failed). No challenge JSON API,")
        print("    no /submit route, no credentials obtainable. The Photo Finish app")
        print("    is not deployed on this port — see NOTES.md.")
        return 1

    # If a real app ever shows up, run the desk flow on any candidate we hold.
    print("\n[desk] POST /submit probing with reconnaissance candidates:")
    for cand in ["", "photo-finish", "8350"]:
        print(f"    {cand!r:14} -> {desk_submit(cand)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
