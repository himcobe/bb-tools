#!/usr/bin/env python3
"""
Clickjacking checker — determines whether a page can be embedded in an
iframe on an attacker-controlled origin. Checks both X-Frame-Options and
the CSP frame-ancestors directive (which supersedes X-Frame-Options in
modern browsers, so a lot of scanners that only check XFO get this wrong).
"""

import sys
import json
import argparse
import re
import urllib.request
import urllib.error

CSP_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.I)


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-clickjack/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers
    except Exception:
        return 0, None


def check_url(url: str) -> dict:
    status, headers = fetch(url)
    if status == 0 or headers is None:
        return {"url": url, "error": "unreachable"}

    lower_headers = {k.lower(): v for k, v in headers.items()}
    xfo = lower_headers.get("x-frame-options")
    csp = lower_headers.get("content-security-policy")

    frame_ancestors = None
    if csp:
        m = CSP_FRAME_ANCESTORS_RE.search(csp)
        if m:
            frame_ancestors = m.group(1).strip()

    # CSP frame-ancestors takes precedence over X-Frame-Options when both are present
    if frame_ancestors is not None:
        protected = "'none'" in frame_ancestors or "'self'" in frame_ancestors
        source = "CSP frame-ancestors"
        detail = frame_ancestors
    elif xfo:
        protected = xfo.strip().upper() in ("DENY", "SAMEORIGIN")
        source = "X-Frame-Options"
        detail = xfo
    else:
        protected = False
        source = None
        detail = None

    return {
        "url": url,
        "status": status,
        "protected": protected,
        "controlling_header": source,
        "value": detail,
        "vulnerable": not protected,
    }


def load_urls(targets: list[str], input_file: str | None) -> list[str]:
    urls = list(targets)
    if input_file:
        with open(input_file) as f:
            urls.extend(line.strip() for line in f if line.strip())
    return urls


def main():
    parser = argparse.ArgumentParser(description="Clickjacking (frameable page) checker")
    parser.add_argument("urls", nargs="*", help="One or more URLs to check")
    parser.add_argument("-i", "--input", help="File with one URL per line")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    urls = load_urls(args.urls, args.input)
    if not urls:
        parser.error("Provide at least one URL or -i/--input file")

    results = []
    for url in urls:
        result = check_url(url)
        results.append(result)
        if result.get("error"):
            print(f"[-] {url}: {result['error']}")
            continue
        if result["vulnerable"]:
            print(f"[MEDIUM] {url} — frameable, no X-Frame-Options or CSP frame-ancestors set")
        else:
            print(f"[+] {url} — protected via {result['controlling_header']} ({result['value']})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
