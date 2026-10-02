# No Strings Attached — MOBILE, 300

**Flag: `safctf{94f40cc66658c67503a859cf383c7622}`**

## Endpoint
- `GET http://54.72.82.22:8130/` — landing page ("COMEBACK KIT"), links `/backup.zip`.
- `GET http://54.72.82.22:8130/backup.zip` — 233,896 bytes, plain ZIP.
  - sha256: `49274b8baa4bd176f3575757c6d82356836ba40eb29d1711a06140a7df7a4688`
  - Port is Apache; no `/submit` route (404). Flag is recovered directly from the artifact.

## What worked (one step)
`backup.zip` is **not** an `.ab` backup — it is a **full Android Studio project source tree**
(`safctfapp/`, Kotlin, Gradle 8.0) including `app/src/main/`, `build/intermediates/`, and
macOS `__MACOSX/` junk. No APK / `classes.dex`; no decompilation needed.

The blurb — *"an archived release note describes a recovery screen that may not exist in this build"* —
is literal. The flag is parked in an **orphaned resource file**:

```
safctfapp/app/src/main/res/values/archive.xml
<resources><string name="archive_auth_token">safctf{94f40cc66658c67503a859cf383c7622}</string></resources>
```

`grep -rn archive_auth_token` over every `.kt`/`.xml`/`.java` in the tree returns **only that
definition** — no activity, fragment, layout or `R.string` reference ever reads it. So "no
strings attached" = the string exists in resources but nothing in the shipped build is attached
to it; the "recovery screen" from the release note was cut from this build, leaving the string
behind. The token name `archive_auth_token` (32 hex inside `safctf{}`) matches the flag format.

## What didn't matter
- `AndroidManifest.xml`: only the standard `MainActivity`; no hidden/non-exported recovery activity.
- `strings.xml`: normal nav strings (`menu_home`/`menu_gallery`/`menu_slideshow`), one decoy line
  `your_are_here_for_the_safCTF`. No flag.
- Kotlin sources (`MainActivity.kt`, three destination fragments/viewmodels) are unmodified
  Android Studio "Navigation Drawer Activity" boilerplate; no crypto/decoding to reverse.
- `build/`, `.gradle/`, `.idea/` hold no flag.

## Reproduce
```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```
Downloads the zip, asserts its sha256, greps every text member for `safctf{...}`, asserts a
single unambiguous match, prints it. Downloaded binaries are kept out of git (sha recorded here).

## Status
Solved. No blockers.
