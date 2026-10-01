import requests, json
U = "http://54.72.82.22:8190/ask"

# 1. What does it say with no body / bad body?
for body in [None, "", "{}", "[]", "notjson", '{"prompt":123}', '{"prompt":null}']:
    try:
        r = requests.post(U, data=body, timeout=15, headers={"Content-Type": "application/json"})
        print("BODY", repr(body), r.status_code, r.text[:250])
    except Exception as e:
        print("BODY", repr(body), "ERR", e)
print("---- key probing ----")
keys = ["prompt", "message", "msg", "query", "q", "input", "text", "transcript",
        "conversation", "history", "session", "session_id", "id", "chat", "ask",
        "content", "data", "instructions", "system", "user"]
for k in keys:
    try:
        r = requests.post(U, json={k: "TESTMARKER123"}, timeout=15)
        t = r.text
        print(k, r.status_code, ("ECHOED" if "TESTMARKER123" in t else "no-echo"), t[:150])
    except Exception as e:
        print(k, "ERR", e)
