#!/usr/bin/env python3
"""
Content/directory discovery — ffuf/dirsearch-style path brute forcer.
Requests a random nonexistent path first to fingerprint the site's "soft
404" (a lot of apps return 200 with a friendly error page instead of a
real 404), then flags any wordlist path whose status/length doesn't match
that baseline.
"""

import sys
import json
import random
import string
import argparse
import urllib.request
import urllib.error
import concurrent.futures

DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "api", "backup", "backups", ".git/config",
    "config", "config.php", "config.json", ".env", ".env.local", "wp-admin",
    "wp-login.php", "phpmyadmin", "server-status", ".well-known/security.txt",
    "robots.txt", "sitemap.xml", "swagger.json", "swagger-ui", "api-docs",
    "graphql", "actuator", "actuator/health", "debug", "test", "staging",
    "internal", "private", "dashboard", "console", "manage", "management",
    ".DS_Store", "web.config", ".htaccess", "crossdomain.xml", "id_rsa",
    "backup.zip", "backup.sql", "backup.tar.gz", "dump.sql", "database.sql",
    "docker-compose.yml", ".git/HEAD", "package.json", "composer.json",
    "phpinfo.php", "info.php", "status", "health", "metrics", "v1", "v2",
]


def fetch(url: str) -> tuple[int, int]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-discover/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read()
            return resp.status, len(body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
            return e.code, len(body)
        except Exception:
            return e.code, 0
    except Exception:
        return 0, 0


def get_baseline(base_url: str) -> tuple[int, int]:
    token = "".join(random.choices(string.ascii_lowercase, k=12))
    return fetch(f"{base_url.rstrip('/')}/{token}-nonexistent-path")


def scan(base_url: str, wordlist: list[str], threads: int = 20) -> list[dict]:
    baseline_status, baseline_len = get_baseline(base_url)
    print(f"[*] Baseline 404 fingerprint: status={baseline_status} length={baseline_len}")

    found = []

    def check(path: str) -> dict | None:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        status, length = fetch(url)
        if status == 0:
            return None
        looks_like_baseline = status == baseline_status and abs(length - baseline_len) < 5
        if looks_like_baseline or status == 404:
            return None
        return {"path": path, "url": url, "status": status, "length": length}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, p): p for p in wordlist}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda r: r["path"])


def main():
    parser = argparse.ArgumentParser(description="Content/directory discovery with soft-404 filtering")
    parser.add_argument("base_url", help="Base URL to scan, e.g. https://target.com")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file (one path per line)")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f if line.strip()]
    else:
        wordlist = DEFAULT_WORDLIST

    print(f"[*] Scanning {args.base_url} with {len(wordlist)} paths...\n")
    found = scan(args.base_url, wordlist, threads=args.threads)

    if not found:
        print("  [-] Nothing interesting found")
    else:
        for r in found:
            print(f"  [{r['status']}] {r['url']} (len={r['length']})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(found, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
