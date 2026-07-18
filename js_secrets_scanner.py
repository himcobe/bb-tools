#!/usr/bin/env python3
"""
JS secrets scanner — pulls script src= URLs off a page (or scans a JS file
directly) and regex-hunts for common leaked-secret patterns: cloud keys,
API tokens, Stripe/Slack keys, private key headers. Matches are masked in
output so you don't accidentally paste a live secret into a report/terminal.
"""

import sys
import json
import argparse
import re
import urllib.request
import urllib.error
import urllib.parse

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key (heuristic)", re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', re.I)),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9A-Za-z]{24,}")),
    ("Generic API Key Assignment", re.compile(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']', re.I)),
    ("Generic Secret Assignment", re.compile(r'(?:secret|client[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']', re.I)),
    ("Bearer Token in Source", re.compile(r'Bearer\s+[A-Za-z0-9\-_.]{20,}')),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Firebase Config", re.compile(r'apiKey["\']?\s*:\s*["\']AIza[0-9A-Za-z\-_]{35}["\']')),
    ("JWT-looking String", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-secrets/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read(3_000_000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.read(3_000_000).decode("utf-8", errors="ignore") if e.fp else ""
    except Exception:
        return ""


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_text(text: str, source: str) -> list:
    findings = []
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            findings.append({"type": name, "source": source, "match": mask(value)})
    return findings


def collect_js_urls(page_url: str, html: str) -> list:
    urls = []
    for m in SCRIPT_SRC_RE.finditer(html):
        src = m.group(1)
        urls.append(urllib.parse.urljoin(page_url, src))
    return urls


def scan(target_url: str) -> dict:
    body = fetch(target_url)
    is_js = target_url.endswith(".js") or "<html" not in body.lower()

    all_findings = []
    if is_js:
        all_findings.extend(scan_text(body, target_url))
        js_urls = [target_url]
    else:
        js_urls = collect_js_urls(target_url, body)
        all_findings.extend(scan_text(body, target_url + " (inline)"))
        for js_url in js_urls:
            js_body = fetch(js_url)
            all_findings.extend(scan_text(js_body, js_url))

    return {"target": target_url, "js_files_checked": len(js_urls), "findings": all_findings}


def main():
    parser = argparse.ArgumentParser(description="JS bundle secrets scanner")
    parser.add_argument("url", help="Page URL (its <script> tags get pulled and scanned) or a direct .js URL")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    print(f"[*] Scanning {args.url}")
    result = scan(args.url)
    print(f"[*] Checked {result['js_files_checked']} JS source(s)")

    if not result["findings"]:
        print("  [+] No obvious secrets found")
    for f_ in result["findings"]:
        print(f"  [HIGH] {f_['type']} in {f_['source']} — {f_['match']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
