#!/usr/bin/env python3
"""Patch MainActivity.smali to bypass all root checks."""

import re

smali_path = "/home/nomad/safaricom_ctf/chal/mobile/secure-vault/apktool_out/smali/com/example/securevault/MainActivity.smali"

with open(smali_path, "r") as f:
    content = f.read()

# Method patterns to patch - replace the entire method body to return "0"
# Each method returns Ljava/lang/String; and we want to return "0"

methods_to_patch = [
    "checkTestKeys",
    "checkRootPackages",
    "checkSuBinary",
    "checkEmulator",
    "checkDebuggableBuild",
    # Note: checkTestKeys appears twice in the list above but it's the same method
]

# For each method, find the method definition and replace its body
# Pattern: .method private final METHOD_NAME()Ljava/lang/String; ... .end method

def patch_method(content, method_name):
    """Replace method body to immediately return '0'."""
    # Find the method
    pattern = rf'(\.method private final {re.escape(method_name)}\(\)Ljava/lang/String;.*?)\.end method'
    
    def replace_method(match):
        method_header = match.group(1)
        # Return a simple method that just returns "0"
        return f"""{method_header}
    .locals 1

    const-string v0, "0"

    return-object v0
.end method"""
    
    return re.sub(pattern, replace_method, content, flags=re.DOTALL)

# Patch all methods
for method in ["checkTestKeys", "checkRootPackages", "checkSuBinary", "checkEmulator", "checkDebuggableBuild"]:
    content = patch_method(content, method)

# Also patch checkTestKeys (it's listed twice but it's the same method)
# The signingCertSha256 method might be used for verification - we'll leave it as is for now
# But we could make it return a valid hash if needed

print("Patching complete")

with open(smali_path, "w") as f:
    f.write(content)

print("Patched MainActivity.smali")