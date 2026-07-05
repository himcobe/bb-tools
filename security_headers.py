#!/usr/bin/env python3
"""
Security headers scanner — checks for missing/weak security headers and
cookie flags across one or more URLs. Fast, low-effort report filler for
programs that reward info-disclosure/misconfiguration findings.
"""

import sys
import json
import argparse
import urllib.request
import urllib.error

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

HEADER_CHECKS = [
    {"header": "Strict-Transport-Security", "severity": "medium",
     "why": "Without HSTS, users can be downgraded to HTTP and MITM'd"},
    {"header": "Content-Security-Policy", "severity": "medium",
     "why": "No CSP means less defense-in-depth against XSS"},
    {"header": "X-Content-Type-Options", "severity": "low",
     "why": "Missing 'nosniff' can let browsers MIME-sniff a response into executing as script"},
    {"header": "X-Frame-Options", "severity": "low",
     "why": "Missing means the page may be embeddable in a clickjacking iframe (unless CSP frame-ancestors covers it)"},
    {"header": "Referrer-Policy", "severity": "info",
     "why": "No policy means the full URL (possibly with tokens) may leak to third parties via Referer"},
    {"header": "Permissions-Policy", "severity": "info",
     "why": "No policy means browser features (camera, geolocation, etc.) aren't explicitly restricted"},
]


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-headers/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers
    except Exception:
        return 0, None


def check_cookies(headers) -> list[dict]:
    findings = []
    cookies = headers.get_all("Set-Cookie") if headers and hasattr(headers, "get_all") else []
    for cookie in cookies or []:
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()
        missing = [flag for flag in ("httponly", "secure", "samesite") if flag not in lower]
        if missing:
            findings.append({"severity": "medium",
                              "message": f"Cookie '{name}' missing: {', '.join(missing)}"})
    return findings


def check_url(url: str) -> dict:
    status, headers = fetch(url)
    if status == 0 or headers is None:
        return {"url": url, "error": "unreachable"}

    lower_headers = {k.lower(): v for k, v in headers.items()}
    findings = []

    for check in HEADER_CHECKS:
        key = check["header"].lower()
        if key not in lower_headers:
            findings.append({"severity": check["severity"], "message": f"Missing {check['header']} — {check['why']}"})
        elif key == "content-security-policy" and "unsafe-inline" in lower_headers[key].lower():
            findings.append({"severity": "low", "message": "CSP present but allows 'unsafe-inline' — weakens XSS protection"})

    findings.extend(check_cookies(headers))
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {"url": url, "status": status, "findings": findings}


def load_urls(targets: list[str], input_file: str | None) -> list[str]:
    urls = list(targets)
    if input_file:
        with open(input_file) as f:
            urls.extend(line.strip() for line in f if line.strip())
    return urls


def main():
    parser = argparse.ArgumentParser(description="Security headers + cookie flag scanner")
    parser.add_argument("urls", nargs="*", help="One or more URLs to check")
    parser.add_argument("-i", "--input", help="File with one URL per line")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    urls = load_urls(args.urls, args.input)
    if not urls:
        parser.error("Provide at least one URL or -i/--input file")

    results = []
    for url in urls:
        print(f"\n[*] Checking {url}")
        result = check_url(url)
        results.append(result)
        if result.get("error"):
            print(f"  [-] {result['error']}")
            continue
        if not result["findings"]:
            print("  [+] All checked headers/cookie flags present")
        for f_ in result["findings"]:
            print(f"  [{f_['severity'].upper():6}] {f_['message']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
