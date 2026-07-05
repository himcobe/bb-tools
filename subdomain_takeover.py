#!/usr/bin/env python3
"""
Subdomain takeover checker — given a list of hostnames, finds ones with a
CNAME pointing at a third-party service (GitHub Pages, Heroku, S3, Azure,
etc.) where the hostname either fails to resolve or serves that provider's
"nothing here" error page, both signs the subdomain can potentially be
claimed by an attacker.
"""

import sys
import json
import random
import string
import argparse
import subprocess
import urllib.request
import urllib.error
import concurrent.futures

# Not exhaustive — extend as you run into new providers.
# Source pattern is the same one https://github.com/EdOverflow/can-i-take-over-xyz uses.
FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": ["github.io"], "signature": "there isn't a github pages site here"},
    {"service": "Heroku", "cname": ["herokuapp.com"], "signature": "no such app"},
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website"], "signature": "nosuchbucket"},
    {"service": "Azure Web Apps", "cname": ["azurewebsites.net"], "signature": "404 web site not found"},
    {"service": "Shopify", "cname": ["myshopify.com"], "signature": "sorry, this shop is currently unavailable"},
    {"service": "Fastly", "cname": ["fastly.net"], "signature": "fastly error: unknown domain"},
    {"service": "Unbounce", "cname": ["unbounce.com"], "signature": "the requested url was not found on this server"},
    {"service": "Zendesk", "cname": ["zendesk.com"], "signature": "help center closed"},
    {"service": "Surge.sh", "cname": ["surge.sh"], "signature": "project not found"},
    {"service": "Netlify", "cname": ["netlify.app", "netlify.com"], "signature": "not found - request id"},
    {"service": "Pantheon", "cname": ["pantheonsite.io"], "signature": "the gods are wise"},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"], "signature": "whatever you were looking for doesn't currently exist"},
    {"service": "WordPress.com", "cname": ["wordpress.com"], "signature": "do you want to register"},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"], "signature": "404 not found"},
    {"service": "Bitbucket", "cname": ["bitbucket.io"], "signature": "repository not found"},
]


def dig(hostname: str, record: str) -> list[str]:
    try:
        out = subprocess.run(
            ["dig", "+short", record, hostname],
            capture_output=True, text=True, timeout=5,
        ).stdout
        return [line.strip().rstrip(".") for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def fetch_body(hostname: str) -> str:
    for scheme in ("https", "http"):
        req = urllib.request.Request(
            f"{scheme}://{hostname}",
            headers={"User-Agent": "Mozilla/5.0 (compatible; bb-tools-takeover/1.0)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.read(8192).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            try:
                return e.read(8192).decode("utf-8", errors="ignore")
            except Exception:
                continue
        except Exception:
            continue
    return ""


def check_hostname(hostname: str) -> dict | None:
    cnames = dig(hostname, "CNAME")
    if not cnames:
        return None

    a_records = dig(hostname, "A")
    resolved = bool(a_records)
    body = fetch_body(hostname).lower()

    for fp in FINGERPRINTS:
        if not any(frag in cname.lower() for cname in cnames for frag in fp["cname"]):
            continue

        matched_signature = fp["signature"] in body
        return {
            "hostname": hostname,
            "cname_chain": cnames,
            "service": fp["service"],
            "resolves": resolved,
            "vulnerable": matched_signature,
            "evidence": fp["signature"] if matched_signature else None,
            "note": None if matched_signature else
                    "CNAME matches a known takeover-prone service but the error signature "
                    "wasn't found — may already be claimed, or the provider changed its error page.",
        }
    return None


def load_hostnames(target: str | None, input_file: str | None) -> list[str]:
    hostnames = []
    if target:
        hostnames.append(target)
    if input_file:
        with open(input_file) as f:
            hostnames.extend(line.strip() for line in f if line.strip())
    return hostnames


def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover checker (dangling CNAME detection)")
    parser.add_argument("target", nargs="?", help="Single hostname to check")
    parser.add_argument("-i", "--input", help="File with one hostname per line")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    hostnames = load_hostnames(args.target, args.input)
    if not hostnames:
        parser.error("Provide a target hostname or -i/--input file")

    print(f"[*] Checking {len(hostnames)} hostname(s) for dangling CNAMEs...\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_hostname, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                if result["vulnerable"]:
                    print(f"  [!!!] {result['hostname']} -> {result['service']} — LIKELY TAKEOVER "
                          f"(evidence: \"{result['evidence']}\")")
                else:
                    print(f"  [~] {result['hostname']} -> {result['service']} — CNAME matches, "
                          f"signature not confirmed (resolves={result['resolves']})")

    if not results:
        print("  [-] No CNAMEs pointing at known takeover-prone services found")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
