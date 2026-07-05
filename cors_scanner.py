#!/usr/bin/env python3
"""
CORS misconfiguration scanner — automates the manual check you did on REA
Group. Sends a random "evil" Origin plus the null origin at each URL and
checks whether Access-Control-Allow-Origin reflects it (or wildcards) while
Access-Control-Allow-Credentials is true, which lets any site read
authenticated responses cross-origin.
"""

import sys
import json
import random
import string
import argparse
import urllib.request
import urllib.error

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def random_evil_origin() -> str:
    token = "".join(random.choices(string.ascii_lowercase, k=10))
    return f"https://{token}-cors-probe.com"


def probe(url: str, origin: str, method: str) -> dict:
    headers = {"Origin": origin, "User-Agent": "Mozilla/5.0 (compatible; bb-tools-cors/1.0)"}
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "GET"
        headers["Access-Control-Request-Headers"] = "Content-Type, Authorization"

    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return dict(resp.headers)
    except urllib.error.HTTPError as e:
        return dict(e.headers) if e.headers else {}
    except Exception:
        return {}


def check_cors(url: str) -> list[dict]:
    evil_origin = random_evil_origin()
    findings = []

    for origin, label in [(evil_origin, "random evil origin"), ("null", "null origin")]:
        for method in ["GET", "OPTIONS"]:
            headers = probe(url, origin, method)
            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if not acao:
                continue

            reflects = acao == origin
            wildcard = acao == "*"

            if reflects and acac:
                findings.append({"url": url, "method": method, "origin_tested": label, "severity": "high",
                                  "detail": f"Reflects arbitrary Origin ({label}) with credentials allowed — "
                                            f"any site can make authenticated requests and read the response"})
            elif wildcard and acac:
                findings.append({"url": url, "method": method, "origin_tested": label, "severity": "high",
                                  "detail": "Wildcard ACAO with Allow-Credentials: true (invalid per spec — "
                                            "some servers/proxies honor it anyway, worth confirming in a browser)"})
            elif reflects:
                findings.append({"url": url, "method": method, "origin_tested": label, "severity": "low",
                                  "detail": f"Reflects arbitrary Origin ({label}) without credentials — "
                                            f"lower impact, still non-standard"})
            elif wildcard:
                findings.append({"url": url, "method": method, "origin_tested": label, "severity": "info",
                                  "detail": "Wildcard ACAO, no credentials — usually fine for a public API"})

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


def load_urls(targets: list[str], input_file: str | None) -> list[str]:
    urls = list(targets)
    if input_file:
        with open(input_file) as f:
            urls.extend(line.strip() for line in f if line.strip())
    return urls


def main():
    parser = argparse.ArgumentParser(description="CORS misconfiguration scanner")
    parser.add_argument("urls", nargs="*", help="One or more endpoint URLs to test")
    parser.add_argument("-i", "--input", help="File with one URL per line")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    urls = load_urls(args.urls, args.input)
    if not urls:
        parser.error("Provide at least one URL or -i/--input file")

    all_findings = {}
    for url in urls:
        print(f"\n[*] Testing {url}")
        findings = check_cors(url)
        all_findings[url] = findings
        if not findings:
            print("  [-] No CORS misconfiguration detected")
            continue
        for f_ in findings:
            print(f"  [{f_['severity'].upper():6}] ({f_['method']}, {f_['origin_tested']}) {f_['detail']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
