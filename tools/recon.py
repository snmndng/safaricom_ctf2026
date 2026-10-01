#!/usr/bin/env python3
"""Quick recon for a CTF web target.

Fingerprints a target and probes common interesting paths. Read-only, no
exploitation -- safe to point at anything in scope.

    .venv/bin/python tools/recon.py http://target:8080
    .venv/bin/python tools/recon.py http://target:8080 --paths extra.txt
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()

TIMEOUT = 8
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"

# Paths that pay off disproportionately often on CTF boxes.
PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config",
    "/.env", "/.env.bak", "/config.php.bak", "/web.config", "/Dockerfile",
    "/docker-compose.yml", "/.dockerignore", "/.htaccess", "/.htpasswd",
    "/backup.zip", "/backup.tar.gz", "/www.zip", "/source.zip", "/app.zip",
    "/admin", "/admin/", "/administrator", "/login", "/dashboard", "/debug",
    "/console", "/actuator", "/actuator/env", "/actuator/health",
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/docs", "/api/swagger.json",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/openapi.json", "/docs",
    "/graphql", "/graphiql", "/v2/api-docs", "/metrics", "/health", "/status",
    "/phpinfo.php", "/info.php", "/test.php", "/server-status",
    "/flag", "/flag.txt", "/flag.php", "/FLAG", "/flag.html",
    "/upload", "/uploads/", "/files/", "/static/", "/assets/",
    "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
    "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
]

INTERESTING_HDRS = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator", "via",
    "x-backend-server", "x-served-by", "set-cookie", "location",
    "x-debug", "x-frame-options", "content-security-policy",
    "access-control-allow-origin", "x-forwarded-for", "x-runtime",
    "x-version", "x-application-context",
]


def head(url: str, s: requests.Session, method: str = "GET") -> requests.Response | None:
    try:
        return s.request(method, url, timeout=TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None


def banner(base: str, r: requests.Response) -> None:
    print(f"\n=== {base} ===")
    print(f"status : {r.status_code} {r.reason}")
    for h in INTERESTING_HDRS:
        if h in r.headers:
            print(f"  {h}: {r.headers[h]}")
    # Title + a few hints from the body.
    body = r.text or ""
    low = body.lower()
    if "<title" in low:
        t = low.split("<title", 1)[1]
        t = t.split(">", 1)[1].split("</title", 1)[0] if ">" in t else ""
        print(f"title  : {t.strip()[:120]}")
    hints = [w for w in ("flask", "django", "express", "laravel", "spring", "tomcat",
                         "nginx", "apache", "werkzeug", "next.js", "react")
             if w in low]
    if hints:
        print(f"hints  : {', '.join(sorted(set(hints)))}")


def probe(base: str, path: str, s: requests.Session) -> tuple[str, int, int] | None:
    url = urljoin(base, path)
    r = head(url, s)
    if r is None:
        return None
    # 404/400/401/403 are mostly noise; 200/301/302/500 are the signal.
    if r.status_code not in (404, 400):
        return (path, r.status_code, len(r.content))
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--paths", help="extra file of paths, one per line")
    ap.add_argument("--threads", type=int, default=16)
    args = ap.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme:
        args.url = "http://" + args.url
    base = args.url.rstrip("/")

    s = requests.Session()
    s.headers["User-Agent"] = UA

    r = head(base, s)
    if r is None:
        print(f"[!] could not connect to {base}", file=sys.stderr)
        return 1
    banner(base, r)

    # Verb behaviour -- quick check for HEAD/OPTIONS/method-based authz.
    print("\n--- methods ---")
    for m in ("HEAD", "OPTIONS", "POST", "PUT", "TRACE"):
        rr = head(base, s, m)
        if rr is not None:
            allow = rr.headers.get("allow", "")
            print(f"  {m:7} -> {rr.status_code}" + (f"  allow: {allow}" if allow else ""))

    paths = list(PATHS)
    if args.paths:
        with open(args.paths, encoding="utf-8", errors="replace") as fh:
            paths += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    print(f"\n--- probing {len(paths)} paths ---")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = [x for x in ex.map(lambda p: probe(base, p, s), paths) if x]
    for path, code, size in sorted(results, key=lambda t: t[1]):
        print(f"  {code}  {size:>8}B  {path}")
    if not results:
        print("  (nothing outside 404/400 -- try a wordlist)")

    print("\n[note] 403/401 on a path is still a signal -- note it and move on.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
