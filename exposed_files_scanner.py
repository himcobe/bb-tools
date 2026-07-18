#!/usr/bin/env python3
"""
Exposed files scanner — checks a target for common sensitive files left
accessible (.env, .git/config, backups, API specs, etc). Uses the same
soft-404 baseline trick as content_discovery.py so a custom "200 OK" error
page doesn't generate false positives.
"""

import sys
import json
import argparse
import random
import string
import urllib.request
import urllib.error

SENSITIVE_PATHS = [
    (".env", "high", "Environment file — often contains DB creds, API keys, secrets"),
    (".env.local", "high", "Environment file — often contains DB creds, API keys, secrets"),
    (".env.production", "high", "Environment file — often contains DB creds, API keys, secrets"),
    (".git/config", "high", "Exposed .git — full source + history may be reconstructable"),
    (".git/HEAD", "high", "Exposed .git — full source + history may be reconstructable"),
    (".aws/credentials", "high", "AWS credentials file"),
    ("id_rsa", "high", "Private SSH key"),
    (".htpasswd", "medium", "htpasswd file — may contain crackable password hashes"),
    ("web.config", "medium", "IIS config — may leak connection strings/internal paths"),
    ("wp-config.php.bak", "high", "WordPress config backup — DB creds in plaintext"),
    ("config.php.bak", "high", "Config backup file — may contain plaintext creds"),
    ("backup.zip", "medium", "Backup archive — may contain source/DB dumps"),
    ("backup.sql", "high", "Database dump — likely contains real user data"),
    ("dump.sql", "high", "Database dump — likely contains real user data"),
    ("docker-compose.yml", "medium", "Docker compose file — may leak internal architecture/env vars"),
    ("Dockerfile", "low", "Dockerfile — internal build details, low sensitivity alone"),
    ("swagger.json", "low", "API spec — full endpoint map, useful for further recon"),
    ("openapi.json", "low", "API spec — full endpoint map, useful for further recon"),
    ("phpinfo.php", "medium", "phpinfo() — leaks full server config/environment"),
    (".npmrc", "medium", "npm config — may contain registry auth tokens"),
    (".DS_Store", "low", "macOS metadata — can leak directory structure"),
    ("composer.json", "info", "PHP dependency manifest — version fingerprinting"),
    ("package.json", "info", "Node dependency manifest — version fingerprinting"),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-exposed/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, resp.read(2000)
    except urllib.error.HTTPError as e:
        body = e.read(2000) if e.fp else b""
        return e.code, body
    except Exception:
        return 0, b""


def get_soft404_baseline(base_url: str) -> tuple:
    junk = "".join(random.choices(string.ascii_lowercase, k=16))
    status, body = fetch(f"{base_url.rstrip('/')}/{junk}.nonexistent")
    return status, len(body)


def scan(base_url: str) -> dict:
    base_url = base_url.rstrip("/")
    baseline_status, baseline_len = get_soft404_baseline(base_url)

    findings = []
    for path, severity, why in SENSITIVE_PATHS:
        status, body = fetch(f"{base_url}/{path}")
        if status == 0:
            continue
        # treat as a real hit only if it doesn't look like the soft-404 baseline
        looks_like_baseline = (status == baseline_status and abs(len(body) - baseline_len) < 15)
        if status == 200 and not looks_like_baseline and len(body) > 0:
            findings.append({"path": path, "severity": severity, "why": why, "status": status})

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {"base_url": base_url, "baseline_status": baseline_status, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="Exposed sensitive files scanner")
    parser.add_argument("target", help="Base URL to scan, e.g. https://target.com")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    print(f"[*] Baselining soft-404 behavior for {args.target}")
    result = scan(args.target)
    print(f"[*] Checked {len(SENSITIVE_PATHS)} known-sensitive paths")

    if not result["findings"]:
        print("  [+] No exposed sensitive files found")
    for f_ in result["findings"]:
        print(f"  [{f_['severity'].upper():6}] /{f_['path']} — {f_['why']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
