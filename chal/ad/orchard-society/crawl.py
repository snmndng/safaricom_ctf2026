#!/usr/bin/env python3
"""Mirror the public Orchard Society pages and same-origin assets."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen
from urllib.error import HTTPError
import hashlib
import json
import re

BASE = 'http://54.72.82.22:8570/'
OUT = Path(__file__).with_name('site-mirror')


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {'a', 'link'} and attrs.get('href'):
            self.urls.append(attrs['href'])
        if tag in {'script', 'img', 'iframe', 'source'} and attrs.get('src'):
            self.urls.append(attrs['src'])
        if tag == 'form':
            self.forms.append({'action': attrs.get('action', ''),
                               'method': attrs.get('method', 'GET')})


def fetch(url):
    try:
        with urlopen(url, timeout=10) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers), error.read()


def main():
    origin = urlparse(BASE).netloc
    queue = ['/', '/robots.txt', '/sitemap.xml', '/health']
    seen, report = set(), []
    while queue:
        route = queue.pop(0)
        if route in seen or len(seen) >= 30:
            continue
        seen.add(route)
        status, headers, body = fetch(urljoin(BASE, route))
        content_type = headers.get('Content-Type', '')
        entry = {'path': route, 'status': status, 'content_type': content_type,
                 'length': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        if status == 200:
            dest = OUT / (route.lstrip('/') or 'index.html')
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            if 'text/html' in content_type:
                html = body.decode('utf-8', errors='replace')
                parser = Links()
                parser.feed(html)
                entry['forms'] = parser.forms
                scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)
                for number, script in enumerate(scripts, 1):
                    (OUT / f'inline-{number}.js').write_text(script + '\n')
                entry['inline_js_paths'] = sorted({
                    path for path in re.findall(r'''['"](/[^'"]+)['"]''', '\n'.join(scripts))
                    if not path.startswith('//')
                })
                urls = parser.urls + re.findall(r'''fetch\(['"]([^'"]+)''', html)
                entry['links'] = urls
                for link in urls:
                    parsed = urlparse(urljoin(BASE, link))
                    if parsed.netloc == origin and parsed.path not in seen:
                        queue.append(parsed.path)
        report.append(entry)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'crawl.json').write_text(json.dumps(report, indent=2) + '\n')
    for entry in report:
        print(entry['status'], entry['path'], entry['content_type'], entry['length'])


if __name__ == '__main__':
    main()
