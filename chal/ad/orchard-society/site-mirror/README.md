# Orchard Society public site mirror

Captured from `http://54.72.82.22:8570/` on 2026-10-02 with
`../crawl.py`. Run that script again to refresh it. `crawl.json` records
HTTP status, response type, size, and SHA-256 for every fetched path.

The page has one `desk` form, one inline stylesheet, one inline script, and
one link to `downloads/orchard-export.zip`. It loads no external JavaScript or
CSS. The script intercepts the form and POSTs JSON `{"answer": value}` to
`/submit`. It contains an alternate `console` branch, but there is no form
with that id on this page. `inline-1.js` is the exact captured script.

The archive contains `directory.json`, `resource-acl.json`, `session.json`,
and `curator-note.txt`; the unpacked contents are in `export/`. The ZIP has no
comment, extra fields, trailing bytes, or data after any JSON value.

`/health` returns `{"status":"ok"}`. `/robots.txt` and `/sitemap.xml` return
404. `/submit` permits POST; the observed receipt responses are 403. The
service does not expose its backend source through the linked files, so this
is a mirror of the public site and artifacts rather than a server-code clone.
