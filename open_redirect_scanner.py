#!/usr/bin/env python3
"""
Open redirect scanner — tries common redirect-looking parameter names
against a URL with an external payload, and checks whether the response
actually sends the browser off-domain (3xx Location header, or a
meta-refresh/JS location assignment reflected in the body).
"""

import sys
import json
import argparse
import re
import urllib.request
import urllib.error
import urllib.parse

COMMON_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnUrl", "return_url", "continue", "dest", "destination", "redir",
    "r", "u", "target", "rurl", "go", "goto", "out", "view", "forward",
]

PAYLOAD_DOMAIN = "evil-redirect-test.example"
PAYLOADS = [
    f"https://{PAYLOAD_DOMAIN}",
    f"//{PAYLOAD_DOMAIN}",
    f"https:{PAYLOAD_DOMAIN}",
    f"/\\/{PAYLOAD_DOMAIN}",
]

META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^"\'>]+)', re.I)
JS_LOCATION_RE = re.compile(r'location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.I)


def fetch_no_redirect(url: str):
    """Fetch without following redirects, so we can inspect the raw Location header."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-redirect/1.0)"})
    try:
        with opener.open(req, timeout=8) as resp:
            return resp.status, resp.headers.get("Location"), resp.read(3000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location"), (e.read(3000).decode("utf-8", errors="ignore") if e.fp else "")
    except Exception:
        return 0, None, ""


def lands_offsite(location: str, body: str) -> bool:
    if location and PAYLOAD_DOMAIN in location:
        return True
    for pattern in (META_REFRESH_RE, JS_LOCATION_RE):
        m = pattern.search(body)
        if m and PAYLOAD_DOMAIN in m.group(1):
            return True
    return False


def test_url(base_url: str, param: str, payload: str) -> dict:
    parsed = urllib.parse.urlsplit(base_url)
    query = urllib.parse.parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urllib.parse.urlencode(query, doseq=True)
    test_url_full = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))

    status, location, body = fetch_no_redirect(test_url_full)
    vulnerable = status in (301, 302, 303, 307, 308) and lands_offsite(location, body)
    if not vulnerable and status == 200:
        vulnerable = lands_offsite("", body)

    return {"param": param, "payload": payload, "url": test_url_full, "status": status,
            "location": location, "vulnerable": vulnerable}


def scan(base_url: str, params: list) -> dict:
    findings = []
    for param in params:
        for payload in PAYLOADS:
            result = test_url(base_url, param, payload)
            if result["vulnerable"]:
                findings.append(result)
                break  # one confirmed payload per param is enough
    return {"base_url": base_url, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="Open redirect scanner")
    parser.add_argument("url", help="Target URL (existing query params are preserved)")
    parser.add_argument("--params", help="Comma-separated custom param names to test instead of the built-in list")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    params = args.params.split(",") if args.params else COMMON_PARAMS
    print(f"[*] Testing {len(params)} parameter names against {args.url}")

    result = scan(args.url, params)

    if not result["findings"]:
        print("  [+] No open redirects found")
    for f_ in result["findings"]:
        print(f"  [HIGH] param='{f_['param']}' payload='{f_['payload']}' -> status={f_['status']} location={f_['location']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
