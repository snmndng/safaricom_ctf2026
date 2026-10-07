#!/usr/bin/env python3
"""Patch MainActivity.smali to bypass all root checks - fixed version."""

import re

smali_path = "/home/nomad/safaricom_ctf/chal/mobile/secure-vault/apktool_out/smali/com/example/securevault/MainActivity.smali"

with open(smali_path, "r") as f:
    content = f.read()

def patch_method(content, method_name):
    """Replace method body to immediately return '0', keeping original .locals."""
    # Pattern: method header, then .locals, then body, then .end method
    pattern = rf'(\.method private final {re.escape(method_name)}\(\)Ljava/lang/String;\n\s*\.locals \d+\n)(.*?)(\.end method)'
    
    def replace_method(match):
        header_and_locals = match.group(1)
        # Replace body with just return "0"
        new_body = """    const-string v0, "0"

    return-object v0
"""
        return header_and_locals + new_body + match.group(3)
    
    return re.sub(pattern, replace_method, content, flags=re.DOTALL)

# Patch all methods
for method in ["checkTestKeys", "checkRootPackages", "checkSuBinary", "checkEmulator", "checkDebuggableBuild"]:
    content = patch_method(content, method)

print("Patching complete")

with open(smali_path, "w") as f:
    f.write(content)

print("Patched MainActivity.smali")