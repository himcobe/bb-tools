#!/usr/bin/env python3
"""
Tech stack fingerprinter — identifies framework/CMS/server from response
headers, cookies, and a handful of body-content signatures. Not a full
Wappalyzer clone, just enough to point recon in the right direction fast.
"""

import sys
import json
import argparse
import re
import urllib.request
import urllib.error

HEADER_SIGNATURES = [
    ("server", re.compile(r"nginx", re.I), "nginx"),
    ("server", re.compile(r"apache", re.I), "Apache"),
    ("server", re.compile(r"microsoft-iis", re.I), "IIS"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare (proxy)"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("x-powered-by", re.compile(r"express", re.I), "Express (Node.js)"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("x-aspnet-version", re.compile(r".+"), "ASP.NET"),
    ("x-drupal-cache", re.compile(r".+"), "Drupal"),
    ("x-generator", re.compile(r"drupal", re.I), "Drupal"),
    ("cf-ray", re.compile(r".+"), "Cloudflare (CDN)"),
    ("x-amz-cf-id", re.compile(r".+"), "Amazon CloudFront"),
    ("x-vercel-id", re.compile(r".+"), "Vercel"),
    ("x-nf-request-id", re.compile(r".+"), "Netlify"),
    ("via", re.compile(r"varnish", re.I), "Varnish"),
    ("x-akamai-transformed", re.compile(r".+"), "Akamai"),
    ("x-fastly-request-id", re.compile(r".+"), "Fastly"),
]

COOKIE_SIGNATURES = [
    (re.compile(r"PHPSESSID", re.I), "PHP"),
    (re.compile(r"JSESSIONID", re.I), "Java (JSP/Servlet)"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"wordpress_", re.I), "WordPress"),
    (re.compile(r"wp-settings", re.I), "WordPress"),
    (re.compile(r"csrftoken", re.I), "Django"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"_rails_session|_session_id", re.I), "Ruby on Rails"),
    (re.compile(r"ci_session", re.I), "CodeIgniter"),
    (re.compile(r"connect\.sid", re.I), "Express (Node.js)"),
    (re.compile(r"__next", re.I), "Next.js"),
]

BODY_SIGNATURES = [
    (re.compile(r"wp-content|wp-includes|wp-json"), "WordPress"),
    (re.compile(r"/sites/default/files|Drupal\.settings"), "Drupal"),
    (re.compile(r"/media/jui/|Joomla!"), "Joomla"),
    (re.compile(r"__NEXT_DATA__|_next/static"), "Next.js"),
    (re.compile(r"data-reactroot|react-dom"), "React"),
    (re.compile(r"ng-version|angular"), "Angular"),
    (re.compile(r'id="app".*vue|__vue__', re.S), "Vue.js"),
    (re.compile(r"csrf-token.*laravel|laravel_session", re.I), "Laravel"),
    (re.compile(r"Shopify\.theme|cdn\.shopify\.com"), "Shopify"),
    (re.compile(r"cdn\.shopifycdn\.com"), "Shopify"),
    (re.compile(r"Powered by Squarespace"), "Squarespace"),
    (re.compile(r"static\.wixstatic\.com"), "Wix"),
]


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-fingerprint/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(200_000).decode("utf-8", errors="ignore")
            return resp.status, resp.headers, body
    except urllib.error.HTTPError as e:
        body = e.read(200_000).decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, e.headers, body
    except Exception:
        return 0, None, ""


def fingerprint(url: str) -> dict:
    status, headers, body = fetch(url)
    if status == 0:
        return {"url": url, "error": "unreachable"}

    found = set()
    lower_headers = {k.lower(): v for k, v in (headers.items() if headers else [])}

    for header_name, pattern, tech in HEADER_SIGNATURES:
        value = lower_headers.get(header_name)
        if value and pattern.search(value):
            found.add(tech)

    cookies = headers.get_all("Set-Cookie") if headers and hasattr(headers, "get_all") else []
    for cookie in cookies or []:
        for pattern, tech in COOKIE_SIGNATURES:
            if pattern.search(cookie):
                found.add(tech)

    for pattern, tech in BODY_SIGNATURES:
        if pattern.search(body):
            found.add(tech)

    return {
        "url": url,
        "status": status,
        "server_header": lower_headers.get("server", "n/a"),
        "technologies": sorted(found) if found else ["unknown"],
    }


def load_urls(targets: list[str], input_file: str | None) -> list[str]:
    urls = list(targets)
    if input_file:
        with open(input_file) as f:
            urls.extend(line.strip() for line in f if line.strip())
    return urls


def main():
    parser = argparse.ArgumentParser(description="Tech stack fingerprinter — headers, cookies, body signatures")
    parser.add_argument("urls", nargs="*", help="One or more URLs to fingerprint")
    parser.add_argument("-i", "--input", help="File with one URL per line")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    urls = load_urls(args.urls, args.input)
    if not urls:
        parser.error("Provide at least one URL or -i/--input file")

    results = []
    for url in urls:
        print(f"\n[*] Fingerprinting {url}")
        result = fingerprint(url)
        results.append(result)
        if result.get("error"):
            print(f"  [-] {result['error']}")
            continue
        print(f"  [+] Server: {result['server_header']}")
        print(f"  [+] Detected: {', '.join(result['technologies'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
