# Archived — XXE (250 pts)

Target: `http://54.72.82.22:8230`
Flag: `safctf{960c0e8a73c24bd9b1aee314ded96157}`

## Endpoint

- `GET /` — Werkzeug/Flask "RELIC SOCIETY" page; JS posts XML to `/fetch_user`.
- `POST /fetch_user` — `Content-Type: application/xml`, body `<request><id>ID</id></request>`.
  - Known ids 1-4 return a user record; unknown ids are echoed back in `<id>`.
  - Error shapes observed:
    - `<error>Missing id element.</error>` — no `<id>` in the document.
    - `<error>Invalid input</error>` — XML parse error (also raised when an
      external entity points at a missing / permission-denied file).

## Vulnerability

The parser resolves external general entities and reflects the expanded value
in the `<id>` element of the response. Classic in-band file read with no OOB
needed.

```xml
<?xml version="1.0"?>
<!DOCTYPE request [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><id>&xxe;</id></request>
```

Bonus: passing a **directory** as the `file://` entity returns a
newline-separated directory listing (e.g. `file:///` -> `bin boot dev etc ...`).
This is what the blurb's *"a catalog card points to a second archive"* means:
list `/` to find the randomised flag filename.

## Exploitation

1. `file:///` lists root, revealing `flag8b9d5b8e264a.txt`.
2. Read `file:///flag8b9d5b8e264a.txt` -> returns the flag in `<id>`.

## Notes / constraints

- `/proc` is not readable through the entity (`Invalid input`), but `/etc`,
  `/usr`, `/sys` and regular dirs are.
- App artifacts on the box: `/home/ctfuser/app.jar` (Tomcat), `/opt/java`,
  `/.rock` — the Flask front is a shim over a Java service.

## Repro

`python solve.py` (uses `requests`) prints the flag.

## Artifacts

No binaries downloaded; nothing to hash.
