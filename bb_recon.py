#!/usr/bin/env python3
"""
Bug bounty recon tool — given a domain, finds GraphQL endpoints,
detects WAF, checks introspection, and hunts JS bundles for query names.
"""

import sys
import re
import json
import time
import argparse
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures


GRAPHQL_PATHS = [
    "/api/graphql", "/graphql", "/gql", "/query",
    "/api/query", "/api/gql", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql", "/graph",
    "/api/graph", "/graphql/v1", "/graphql/v2",
    "/data", "/api/data",
]

JS_PATHS_TO_HUNT = [
    "/static/js/main.chunk.js", "/static/js/bundle.js",
    "/_next/static/chunks/pages/_app.js",
    "/assets/index.js", "/js/app.js", "/js/main.js",
]

WAF_SIGNATURES = {
    "Akamai": ["bm_sz", "ak_bmsc", "_abck", "akacd_"],
    "Cloudflare": ["__cfduid", "cf_clearance", "cf-ray"],
    "Incapsula": ["incap_ses", "visid_incap"],
    "Fastly": ["x-fastly"],
    "AWS WAF": ["x-amzn-trace-id", "awsalb"],
    "F5": ["TS01", "TSPD_101"],
    "Akamai Bot Manager": ["bm_sv", "bm_mi", "bm_so"],
}

INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'

GRAPHQL_QUERY_PATTERN = re.compile(
    r'(?:query|mutation|subscription)\s+(\w+)\s*[\({]', re.MULTILINE
)

OPERATION_NAME_PATTERN = re.compile(
    r'operationName["\s:]+["\'`](\w+)["\s\'`]'
)


def fetch(url: str, method: str = "GET", data: bytes | None = None,
          headers: dict | None = None, timeout: int = 10) -> tuple[int, dict, bytes]:
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; bb-tools-recon/1.0)"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read()
        except Exception:
            return e.code, {}, b""
    except Exception as e:
        return 0, {}, str(e).encode()


def detect_waf(headers: dict, cookies_str: str) -> list[str]:
    detected = []
    combined = " ".join(headers.keys()).lower() + " " + cookies_str.lower()
    combined += " " + " ".join(str(v).lower() for v in headers.values())
    for waf, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            detected.append(waf)
    return list(set(detected))


def check_graphql(base: str, path: str) -> dict | None:
    url = base.rstrip("/") + path
    # send introspection
    status, headers, body = fetch(
        url, "POST",
        data=INTROSPECTION_QUERY.encode(),
        headers={"Content-Type": "application/json", "Origin": base}
    )
    if status == 0:
        return None

    result = {"url": url, "status": status, "introspection": False, "waf": []}
    cookies = headers.get("Set-Cookie", "")
    result["waf"] = detect_waf(headers, cookies)

    try:
        parsed = json.loads(body)
        if "data" in parsed and "__schema" in parsed.get("data", {}):
            result["introspection"] = True
        elif "errors" in parsed:
            # endpoint exists, introspection blocked
            result["exists"] = True
        elif status in (200, 400):
            result["exists"] = True
    except Exception:
        if status == 200:
            result["exists"] = True

    if result.get("introspection") or result.get("exists"):
        return result
    if status not in (404, 0):
        result["exists"] = True
        return result
    return None


def hunt_js_for_queries(base: str) -> list[str]:
    found = set()

    # first try to find JS files from the homepage
    status, headers, body = fetch(base)
    if status == 200:
        html = body.decode("utf-8", errors="ignore")
        # find script src tags
        js_refs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
        for ref in js_refs[:20]:  # limit
            if ref.startswith("http"):
                js_url = ref
            elif ref.startswith("/"):
                js_url = base.rstrip("/") + ref
            else:
                js_url = base.rstrip("/") + "/" + ref

            _, _, js_body = fetch(js_url, timeout=15)
            js_text = js_body.decode("utf-8", errors="ignore")
            ops = GRAPHQL_QUERY_PATTERN.findall(js_text)
            ops += OPERATION_NAME_PATTERN.findall(js_text)
            found.update(ops)

    # also probe known paths
    for path in JS_PATHS_TO_HUNT:
        _, _, js_body = fetch(base.rstrip("/") + path, timeout=15)
        if js_body:
            js_text = js_body.decode("utf-8", errors="ignore")
            ops = GRAPHQL_QUERY_PATTERN.findall(js_text)
            ops += OPERATION_NAME_PATTERN.findall(js_text)
            found.update(ops)

    return sorted(found)


def check_cors(graphql_url: str) -> dict:
    _, headers, _ = fetch(
        graphql_url, "OPTIONS",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
    )
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    return {
        "allow_origin": acao,
        "allow_credentials": acac,
        "wildcard": acao == "*",
        "reflects_origin": acao == "https://evil.com",
    }


def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon — GraphQL discovery + WAF + JS query mining")
    parser.add_argument("domain", help="Target domain (e.g. shop.target.com)")
    parser.add_argument("--https", action="store_true", default=True, help="Use HTTPS (default)")
    parser.add_argument("--http", action="store_true", help="Use HTTP")
    parser.add_argument("--js", action="store_true", help="Hunt JS bundles for GraphQL operation names")
    parser.add_argument("--cors", action="store_true", help="Check CORS on found GraphQL endpoints")
    parser.add_argument("-o", "--output", help="Save JSON results to file")
    args = parser.parse_args()

    scheme = "http" if args.http else "https"
    base = f"{scheme}://{args.domain.lstrip('http://').lstrip('https://')}"

    print(f"\n[*] Target: {base}")
    print(f"[*] Probing {len(GRAPHQL_PATHS)} GraphQL paths...\n")

    results = {"target": base, "graphql_endpoints": [], "js_operations": [], "waf": []}

    # probe GraphQL endpoints in parallel
    found_endpoints = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check_graphql, base, path): path for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_endpoints.append(result)
                intro = "[INTROSPECTION ON]" if result.get("introspection") else "[introspection off]"
                waf = f" WAF: {', '.join(result['waf'])}" if result.get("waf") else ""
                print(f"  [+] {result['url']} {intro}{waf}")

    results["graphql_endpoints"] = found_endpoints

    # collect WAFs
    all_wafs = set()
    for ep in found_endpoints:
        all_wafs.update(ep.get("waf", []))
    results["waf"] = list(all_wafs)

    if not found_endpoints:
        print("  [-] No GraphQL endpoints found")

    # CORS check
    if args.cors and found_endpoints:
        print(f"\n[*] Checking CORS...")
        for ep in found_endpoints:
            cors = check_cors(ep["url"])
            ep["cors"] = cors
            if cors.get("wildcard") or cors.get("reflects_origin"):
                print(f"  [!] CORS ISSUE on {ep['url']}: origin={cors['allow_origin']} creds={cors['allow_credentials']}")
            else:
                print(f"  [-] {ep['url']}: origin={cors['allow_origin'] or 'none'}")

    # JS mining
    if args.js:
        print(f"\n[*] Mining JS bundles for GraphQL operations...")
        ops = hunt_js_for_queries(base)
        results["js_operations"] = ops
        if ops:
            print(f"  [+] Found {len(ops)} operation names:")
            for op in ops[:50]:
                print(f"      {op}")
            if len(ops) > 50:
                print(f"      ... and {len(ops)-50} more")
        else:
            print("  [-] No operation names found")

    # Summary
    print(f"\n=== SUMMARY ===")
    print(f"  GraphQL endpoints: {len(found_endpoints)}")
    print(f"  WAF detected:      {', '.join(results['waf']) or 'none'}")
    if args.js:
        print(f"  JS operations:     {len(results['js_operations'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
