#!/usr/bin/env python3
"""Generate detailed CTF writeups from the authentic NOTES.md + solve.py.

Unlike the first version (which tried to auto-summarise and produced terse
"run this script" stubs), this preserves the real discovery trail recorded in
each challenge's NOTES.md — that *is* the "how we found it" narrative — and
appends the full solve script plus a tools section (tools we used, detected
from the code and notes, and tools you could also reach for, per category).

Hand-written detailed writeups (orchard-society, long-exposure,
midnight-feedback, photo-finish, mr-beast-configuration, inner-joiner) are NOT
in CHALLENGE_INFO and are therefore never overwritten by this generator.
"""

import re
import subprocess
from pathlib import Path

CHAL_DIR = Path("chal")
OUTPUT_DIR = Path("writeups")
OUTPUT_DIR.mkdir(exist_ok=True)

CHALLENGE_INFO = {
    "ad/crown-studio": {"cat": "AD", "pts": 750, "diff": "hard", "title": "Crown Studio"},
    "ad/winter-pavilion": {"cat": "AD", "pts": 500, "diff": "medium", "title": "Winter Pavilion"},
    "ai/fragments": {"cat": "AI", "pts": 300, "diff": "medium", "title": "Fragments"},
    "api/backstage-ledger": {"cat": "API", "pts": 500, "diff": "medium", "title": "Backstage Ledger"},
    "api/night-bus": {"cat": "API", "pts": 300, "diff": "medium", "title": "Night Bus"},
    "cloud/greenroom-atlas": {"cat": "CLOUD", "pts": 750, "diff": "hard", "title": "Greenroom Atlas"},
    "cloud/harbor-lights": {"cat": "CLOUD", "pts": 300, "diff": "medium", "title": "Harbor Lights"},
    "cloud/stageworks": {"cat": "CLOUD", "pts": 500, "diff": "medium", "title": "Stageworks"},
    "crypto/midnight-parcel": {"cat": "CRYPTO", "pts": 750, "diff": "hard", "title": "Midnight Parcel"},
    "crypto/parallel-lines": {"cat": "CRYPTO", "pts": 500, "diff": "medium", "title": "Parallel Lines"},
    "crypto/three-encores": {"cat": "CRYPTO", "pts": 300, "diff": "medium", "title": "Three Encores"},
    "cve/fan-signal-lab": {"cat": "CVE", "pts": 150, "diff": "easy", "title": "Fan Signal Lab"},
    "forensics/fancy-details": {"cat": "FORENSICS", "pts": 300, "diff": "medium", "title": "Fancy Details"},
    "forensics/matchday-replay": {"cat": "FORENSICS", "pts": 300, "diff": "medium", "title": "Matchday Replay"},
    "forensics/second-pressing": {"cat": "FORENSICS", "pts": 500, "diff": "medium", "title": "Second Pressing"},
    "misc/afterparty-crew": {"cat": "MISC", "pts": 300, "diff": "medium", "title": "Afterparty Crew"},
    "misc/double-feature": {"cat": "MISC", "pts": 300, "diff": "medium", "title": "Double Feature"},
    "misc/pitlane-desk": {"cat": "MISC", "pts": 300, "diff": "medium", "title": "Pitlane Desk"},
    "misc/signal-garden": {"cat": "MISC", "pts": 300, "diff": "medium", "title": "Signal Garden"},
    "misc/ticket-carousel": {"cat": "MISC", "pts": 300, "diff": "medium", "title": "Ticket Carousel"},
    "misc/workshop-nocturne": {"cat": "MISC", "pts": 500, "diff": "medium", "title": "Workshop Nocturne"},
    "mobile/comeback-pocket": {"cat": "MOBILE", "pts": 300, "diff": "medium", "title": "Comeback Pocket"},
    "mobile/glass-arcade": {"cat": "MOBILE", "pts": 750, "diff": "hard", "title": "Glass Arcade"},
    "mobile/northern-lights": {"cat": "MOBILE", "pts": 500, "diff": "hard", "title": "Northern Lights"},
    "mobile/no-strings-attached": {"cat": "MOBILE", "pts": 300, "diff": "medium", "title": "No Strings Attached"},
    "mobile/secure-vault": {"cat": "MOBILE", "pts": 300, "diff": "medium", "title": "Secure Vault"},
    "osint/blue-meridian": {"cat": "OSINT", "pts": 750, "diff": "hard", "title": "Blue Meridian"},
    "osint/last-tram-home": {"cat": "OSINT", "pts": 500, "diff": "hard", "title": "Last Tram Home"},
    "osint/paper-lanterns": {"cat": "OSINT", "pts": 300, "diff": "medium", "title": "Paper Lanterns"},
    "pwn/encore": {"cat": "PWN", "pts": 500, "diff": "medium", "title": "Encore"},
    "pwn/moonbase-radio": {"cat": "PWN", "pts": 500, "diff": "medium", "title": "Moonbase Radio"},
    "pwn/neon-cabaret": {"cat": "PWN", "pts": 300, "diff": "medium", "title": "Neon Cabaret"},
    "pwn/overtime": {"cat": "PWN", "pts": 320, "diff": "medium", "title": "Overtime"},
    "rev/clockwork-ballet": {"cat": "REV", "pts": 500, "diff": "medium", "title": "Clockwork Ballet"},
    "rev/pixel-courier": {"cat": "REV", "pts": 150, "diff": "easy", "title": "Pixel Courier"},
    "rev/prism-orchestra": {"cat": "REV", "pts": 750, "diff": "hard", "title": "Prism Orchestra"},
    "web/citrus-proof": {"cat": "WEB", "pts": 750, "diff": "hard", "title": "Citrus Proof"},
    "web/ginger-juice-shop": {"cat": "WEB", "pts": 350, "diff": "medium", "title": "Ginger Juice Shop"},
    "web/head-office": {"cat": "WEB", "pts": 250, "diff": "easy", "title": "HEAD Office"},
    "web/internal-affairs": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Internal Affairs"},
    "web/jwt-forgery": {"cat": "WEB", "pts": 150, "diff": "easy", "title": "JWT Forgery"},
    "web/know-your-limits": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Know Your Limits"},
    "web/lightweight-directory": {"cat": "WEB", "pts": 400, "diff": "medium", "title": "Lightweight Directory"},
    "web/prompt-pirate": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Prompt Pirate"},
    "web/quick-recovery": {"cat": "WEB", "pts": 150, "diff": "easy", "title": "Quick Recovery"},
    "web/secret-vault": {"cat": "WEB", "pts": 450, "diff": "medium", "title": "Secret Vault"},
    "web/sneaky-includes": {"cat": "WEB", "pts": 150, "diff": "easy", "title": "Sneaky Includes"},
    "web/ssti-secrets": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "SSTI Secrets"},
    "web/templated-malice": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Templated Malice"},
    "web/tomcat-path-traversal": {"cat": "WEB", "pts": 450, "diff": "medium", "title": "Tomcat Path Traversal"},
    "web/touchline-dispatch": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Touchline Dispatch"},
    "web/upload-your-art": {"cat": "WEB", "pts": 300, "diff": "medium", "title": "Upload Your Art"},
    "web/velvet-rehearsal": {"cat": "WEB", "pts": 500, "diff": "hard", "title": "Velvet Rehearsal"},
    "web/you-snitch": {"cat": "WEB", "pts": 450, "diff": "medium", "title": "You Snitch"},
    "xxe/archived": {"cat": "XXE", "pts": 250, "diff": "medium", "title": "Archived"},
}

CAT_MAP = {
    "AD": "ad", "AI": "ai-ml", "API": "web", "CLOUD": "cloud", "CRYPTO": "crypto",
    "CVE": "malware", "FORENSICS": "forensics", "MISC": "misc", "MOBILE": "malware",
    "OSINT": "osint", "PWN": "pwn", "REV": "reverse", "WEB": "web", "XXE": "web",
}

# --- Tool detection -------------------------------------------------------
# Python-import -> human tool label (what the solver actually leaned on).
PYLIB_TOOLS = {
    "requests": "Python `requests` (HTTP client)",
    "urllib": "Python `urllib` (stdlib HTTP client)",
    "httpx": "Python `httpx`",
    "socket": "Python `socket` (raw TCP)",
    "pwn": "pwntools",
    "Crypto": "PyCryptodome",
    "cryptography": "`cryptography` (AEAD/AES)",
    "hashlib": "`hashlib`",
    "hmac": "`hmac`",
    "z3": "z3 SMT solver",
    "sage": "SageMath",
    "sympy": "SymPy",
    "gmpy2": "gmpy2",
    "numpy": "NumPy",
    "PIL": "Pillow (imaging)",
    "cv2": "OpenCV",
    "pyzbar": "pyzbar (QR/barcode)",
    "scapy": "Scapy",
    "struct": "`struct` (binary parsing)",
    "zipfile": "`zipfile`",
    "tarfile": "`tarfile`",
    "sqlite3": "`sqlite3`",
    "plistlib": "`plistlib`",
    "jwt": "PyJWT",
    "base64": "`base64`",
    "itertools": "`itertools`",
}
# CLI / GUI tools matched as whole words in NOTES + solve text.
CLI_TOOLS = {
    r"\bnmap\b": "nmap",
    r"\bffuf\b": "ffuf",
    r"\bgobuster\b": "gobuster",
    r"\bferoxbuster\b": "feroxbuster",
    r"\bwfuzz\b": "wfuzz",
    r"\bcurl\b": "curl",
    r"\bwget\b": "wget",
    r"\bnetcat\b": "netcat (nc)",
    r"\bsqlmap\b": "sqlmap",
    r"\bnikto\b": "nikto",
    r"\bjadx\b": "jadx",
    r"\bapktool\b": "apktool",
    r"\bdex2jar\b": "dex2jar",
    r"\bfrida\b": "Frida",
    r"\bobjection\b": "objection",
    r"\badb\b": "adb",
    r"\bkeytool\b": "keytool",
    r"\bghidra\b": "Ghidra",
    r"\bradare2\b|\brizin\b": "radare2/rizin",
    r"\bpwndbg\b|\bGEF\b": "GDB (pwndbg/GEF)",
    r"\bobjdump\b": "objdump",
    r"\breadelf\b": "readelf",
    r"\bchecksec\b": "checksec",
    r"\bROPgadget\b|\bropgadget\b": "ROPgadget",
    r"\bone_gadget\b": "one_gadget",
    r"\bpatchelf\b": "patchelf",
    r"\bbinwalk\b": "binwalk",
    r"\bforemost\b": "foremost",
    r"\bexiftool\b": "exiftool",
    r"\bzsteg\b": "zsteg",
    r"\bsteghide\b": "steghide",
    r"\bstegsolve\b": "StegSolve",
    r"\bzbarimg\b": "zbarimg",
    r"\btshark\b|\bwireshark\b": "Wireshark/tshark",
    r"\bvolatility\b|\bvol3\b": "Volatility",
    r"\bjohn\b": "John the Ripper",
    r"\bhashcat\b": "hashcat",
    r"\bopenssl\b": "openssl",
    r"\bcyberchef\b|\bCyberChef\b": "CyberChef",
    r"\bbloodhound\b|\bBloodHound\b": "BloodHound",
    r"\bcertipy\b": "Certipy",
    r"\bimpacket\b": "impacket",
    r"\bldapsearch\b": "ldapsearch",
    r"\bkubectl\b": "kubectl",
    r"\bburp\b|\bBurp\b": "Burp Suite",
    r"\bjq\b": "jq",
}
# What else a solver could reach for, by category.
CAT_TOOLBOX = {
    "WEB": ["Burp Suite / mitmproxy (intercept + repeat)", "ffuf / feroxbuster (content & parameter discovery)",
            "sqlmap (automated SQLi)", "tplmap (SSTI)", "jwt_tool (JWT attacks)", "nikto", "nuclei"],
    "API": ["Burp Suite (repeater/intruder)", "ffuf (endpoint & param fuzzing)", "Postman/httpie", "jwt_tool", "arjun (param mining)"],
    "XXE": ["Burp Suite + the Collaborator (OOB XXE)", "ffuf", "`defusedxml` (to study the fixed behaviour)", "XXEinjector"],
    "AD": ["BloodHound / SharpHound (graph the domain)", "Certipy (AD CS / ESC1-8)", "impacket (ntlmrelayx, secretsdump)", "ldapsearch", "crackmapexec / NetExec"],
    "CLOUD": ["aws CLI + Pacu (AWS exploitation)", "kubectl (K8s API)", "ScoutSuite / Prowler (posture)", "kube-hunter"],
    "CRYPTO": ["SageMath (lattices, curves, polynomials)", "z3 (constraint solving)", "RsaCtfTool (RSA attacks)", "sympy / gmpy2 (number theory)", "fpylll (LLL/BKZ lattices)"],
    "CVE": ["searchsploit / Exploit-DB", "Metasploit", "nuclei (templated CVE checks)", "the public PoC for the CVE"],
    "MALWARE": ["CyberChef (decode/deobfuscate)", "YARA (classification)", "dnSpy / ILSpy (.NET)", "FLOSS (obfuscated strings)", "a sandbox (any.run / cuckoo)"],
    "FORENSICS": ["Wireshark / tshark (pcap)", "Volatility 3 (memory)", "binwalk + foremost (carving)", "exiftool (metadata)", "zsteg / StegSolve (image stego)", "The Sleuth Kit / Autopsy (disk)"],
    "MISC": ["CyberChef (encoding chains)", "z3 / SageMath (constraints)", "pwntools (interaction)", "Ciphey (auto-decode)"],
    "MOBILE": ["jadx / jadx-gui (DEX -> Java)", "apktool (resources + smali)", "Frida + objection (runtime hooking)", "dex2jar + JD-GUI", "adb (device/backup)", "keytool / apksigner"],
    "OSINT": ["exiftool (media metadata)", "the Wayback Machine / archive.today", "Google/GitHub dorking", "sherlock / maigret (username pivots)", "reverse image search (Yandex/Google)", "whois / crt.sh / dnsrecon"],
    "PWN": ["pwntools (exploit dev)", "GDB + pwndbg/GEF", "Ghidra / IDA (static)", "radare2 / rizin", "ROPgadget / ropper", "one_gadget", "checksec, patchelf"],
    "REV": ["Ghidra / IDA Free (decompile)", "radare2 / rizin (+ Cutter)", "angr (symbolic execution)", "GDB (dynamic)", "dnSpy (.NET), uncompyle6 (Python)", "Binary Ninja"],
}


def get_flags(chal_path):
    """All safctf{...} values FLAGS.md records for this challenge (answer + receipt)."""
    try:
        result = subprocess.run(["grep", f" {chal_path} ", "FLAGS.md"],
                                 capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            flags = re.findall(r'`(safctf\{[^}]+\})`', result.stdout)
            seen, out = set(), []
            for f in flags:
                if f not in seen:
                    seen.add(f); out.append(f)
            return out
    except Exception:
        pass
    return []


def read(chal_path, name):
    p = CHAL_DIR / chal_path / name
    return p.read_text() if p.exists() else ""


def clean_notes(notes):
    """Keep the authentic discovery trail; drop the parts frontmatter duplicates.

    Removes the leading H1, standalone **Flag:**/metadata bullets at the top,
    and a redundant top-level `## Flag` section — the narrative, tables, dead
    ends, and reproduce steps are all preserved verbatim.
    """
    lines = notes.split("\n")
    i, n = 0, len(lines)
    while i < n and not lines[i].strip():
        i += 1
    if i < n and lines[i].startswith("# "):
        i += 1
    meta_re = re.compile(r"^\s*[-*]?\s*\*{0,2}(Flag|Category|Points|Branch|Status|Difficulty)\b", re.I)
    out, skipping_flag_section = [], False
    for line in lines[i:]:
        if re.match(r"^##\s+Flag\b", line, re.I):
            skipping_flag_section = True
            continue
        if skipping_flag_section:
            if line.startswith("## "):
                skipping_flag_section = False
            else:
                continue
        if meta_re.match(line):
            continue
        out.append(line)
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def detect_tools(notes, solve, extra_files):
    used, seen = [], set()

    def add(label):
        if label and label not in seen:
            seen.add(label); used.append(label)

    code = "\n".join([solve] + list(extra_files.values()))
    for m in re.finditer(r"^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)", code, re.M):
        root = m.group(1).split(".")[0]
        if root in PYLIB_TOOLS:
            add(PYLIB_TOOLS[root])
    if solve.strip() or extra_files:
        add("Python 3 (solver)")
    hay = notes + "\n" + code
    for pat, label in CLI_TOOLS.items():
        if re.search(pat, hay):
            add(label)
    return used


def pick_solver_files(chal_path):
    """solve.py plus a couple of same-folder helper scripts when present."""
    folder = CHAL_DIR / chal_path
    files = {}
    for name in ("solve.py", "solve.sh", "exploit.py", "exploit.sh"):
        if (folder / name).exists():
            files[name] = (folder / name).read_text()
    return files


def fence_for(name):
    if name.endswith(".sh"):
        return "bash"
    if name.endswith(".py"):
        return "python"
    return ""


def generate(chal_path, info):
    cat = CAT_MAP.get(info["cat"], info["cat"].lower())
    notes = read(chal_path, "NOTES.md")
    solve_files = pick_solver_files(chal_path)
    solve_main = solve_files.get("solve.py", "")
    flags = get_flags(chal_path)

    tools_used = detect_tools(notes, solve_main, solve_files)
    toolbox = CAT_TOOLBOX.get(info["cat"]) or CAT_TOOLBOX["MISC"]

    body = clean_notes(notes) if notes else "_No notes recorded._"

    out = [
        "---",
        f'title: "{info["title"]}"',
        'ctf: "Safaricom CTF"',
        "date: 2026-10-06",
        f"category: {cat}",
        f'difficulty: {info["diff"]}',
        f'points: {info["pts"]}',
        'flag_format: "safctf{...}"',
        'author: "Strawhats"',
        "---",
        "",
        f'# {info["title"]}',
        "",
        f'> **Category:** {info["cat"]} · **Points:** {info["pts"]} · '
        f'**Difficulty:** {info["diff"]}',
        "",
        "## Discovery, analysis & exploitation",
        "",
        "The full hunt below is reproduced from our working notes — recon,"
        " fingerprinting, the bug, dead ends, and the path to the flag.",
        "",
        body,
        "",
    ]

    if solve_files:
        out += ["## Solve script", ""]
        for name, content in solve_files.items():
            out += [f"`{chal_path}/{name}`:", "", f"```{fence_for(name)}", content.rstrip(), "```", ""]

    out += ["## Tools", "", "**Used in this solve:**", ""]
    out += [f"- {t}" for t in tools_used] or ["- Python 3"]
    out += ["", "**Other tools that fit this category:**", ""]
    out += [f"- {t}" for t in toolbox]
    out += [""]

    out += ["## Flag", ""]
    if len(flags) >= 2:
        out += [f"Intermediate answer: `{flags[0]}`  ", f"Graded flag: `{flags[1]}`", "", "```", flags[1], "```"]
    elif len(flags) == 1:
        out += ["```", flags[0], "```"]
    else:
        out += ["_Not captured (see notes above)._"]
    out += [""]

    text = "\n".join(out)
    safe = chal_path.replace("/", "-")
    (OUTPUT_DIR / f"writeup-{safe}.md").write_text(text)
    return safe, len(tools_used)


def main():
    print(f"Generating detailed writeups for {len(CHALLENGE_INFO)} challenges...")
    for chal_path, info in CHALLENGE_INFO.items():
        try:
            safe, ntools = generate(chal_path, info)
            print(f"  ok {safe} ({ntools} tools detected)")
        except Exception as e:
            print(f"  FAIL {chal_path}: {e}")
    print("Done.")


if __name__ == "__main__":
    main()
