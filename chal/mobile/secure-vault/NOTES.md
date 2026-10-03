# Secure Vault — MOBILE

Target: `com.example.securevault` (Flutter + native Android, `SecureVault_v1.apk`)
Flag: `safctf{d9d4c9e7-0f00-48dd-937d-0337bfb14baa}`

## What it actually is

A Flutter app with native root/emulator/debug detection via a MethodChannel
(`securevault/rootcheck`). The app performs six integrity checks before
provisioning the secret into a local SQLite database (`vault.db`).

## The checks (in `MainActivity.java`)

| Method | What it detects |
| --- | --- |
| `checkTestKeys` | `Build.TAGS == "test-keys"` |
| `checkRootPackages` | Common root packages (`SuperSU`, `Magisk`, etc.) |
| `checkSuBinary` | `su` binary in common paths |
| `checkEmulator` | Emulator build props (`ro.product.model=sdk`, etc.) |
| `checkDebuggableBuild` | `ApplicationInfo.FLAG_DEBUGGABLE` |
| `signingCertSha256` | Compares cert SHA-256 against hardcoded value |

Each check returns `"1"` (dirty) or `"0"` (clean) via the MethodChannel to
Flutter. Flutter calls `vetAndProvision` on the native bridge; only if **all
six return `"0"`** does it write the flag into the vault table:

```sql
CREATE TABLE vault (id INTEGER PRIMARY KEY, secret TEXT);
-- After successful integrity scan:
INSERT INTO vault (secret) VALUES ('safctf{...}');
```

## Solution

The app is **not** `debuggable`, so `run-as` doesn't work on the database.
However, `adb root` allows pulling the database directly.

```bash
# 1. Install the original APK (it installs cleanly; patched APKs fail native lib extraction)
adb install SecureVault_v1.apk

# 2. Launch the app once so it creates the database
adb shell am start -n com.example.securevault/.MainActivity

# 3. Pull the vault database as root (the flag is already provisioned on first run)
adb root
adb shell "cp /data/data/com.example.securevault/databases/vault.db /sdcard/vault.db && chmod 644 /sdcard/vault.db"
adb pull /sdcard/vault.db

# 4. Read the flag
sqlite3 vault.db "SELECT * FROM vault;"
# 1|safctf{d9d4c9e7-0f00-48dd-937d-0337bfb14baa}
```

No Frida hooking or runtime patching was needed—the flag is provisioned on
first launch regardless of the root checks (the checks only gate the UI
"Vault" screen, not the initial database write).

## Files

- `SecureVault_v1.apk` — original APK
- `patch_smali.py`, `patch_smali_v2.py` — attempted smali patches (not needed)
- `frida/` — Frida scripts for runtime hooking (not needed)
- `apktool_out/`, `jadx_out/`, `extracted/` — reverse-engineering artifacts