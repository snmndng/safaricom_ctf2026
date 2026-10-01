import requests, json
B = "http://54.72.82.22:8190"
paths = ["/transcript", "/transcripts", "/conversation", "/conversations", "/history",
         "/chat", "/api", "/api/ask", "/api/chat", "/api/transcript", "/api/conversations",
         "/session", "/sessions", "/export", "/logs", "/redacted", "/missing",
         "/health", "/status", "/robots.txt", "/sitemap.xml", "/flag", "/admin", "/debug"]
for p in paths:
    for method in ("GET",):
        try:
            r = requests.request(method, B+p, timeout=15)
            body = r.text[:200].replace("\n", " ")
            print(method, p, r.status_code, len(r.text), body[:160])
        except Exception as e:
            print(method, p, "ERR", e)
