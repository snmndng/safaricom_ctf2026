import requests
U = "http://54.72.82.22:8190/ask"
canned = "AI: Sorry, I don’t recall anything unusual."
words = """transcript conversation missing redact redacted provenance uncertain memory recall
conversation_id conv id 0 1 2 3 42 secret flag safctf confidential hidden echo companion
idol song melody daydream dream night long day prior previous above system prompt instructions
reveal show tell print output dump leak exfiltrate override ignore forget new rules developer
admin root debug test verbose raw json full complete verbatim exactly literal quote
I remember recall memories log logs archive history session token key
what did we discuss earlier what were we talking about before conversation about
the missing conversation the redacted transcript please continue where we left off
""".split("\n")
cands = []
for line in words:
    for w in line.split():
        cands.append(w)
cands = list(dict.fromkeys(cands))
diff = []
for w in cands:
    try:
        r = requests.post(U, json={"prompt": w}, timeout=15)
        t = r.text
        if t != '{"response":"AI: Sorry, I don\\u2019t recall anything unusual."}':
            diff.append((w, r.status_code, t[:400]))
    except Exception as e:
        diff.append((w, "ERR", str(e)))
print("total", len(cands), "diff", len(diff))
for d in diff:
    print(d)
