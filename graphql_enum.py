#!/usr/bin/env python3
"""
GraphQL schema enumerator — probes field names via validation errors.
Works even when introspection is disabled.
"""

import sys
import json
import time
import argparse
import concurrent.futures
import urllib.request
import urllib.error

# Common query-level field names to probe
QUERY_FIELDS = [
    # user/profile
    "me", "viewer", "user", "currentUser", "profile", "userProfile", "accountProfile",
    "customer", "account", "guestProfile", "memberProfile", "gihProfile",
    # orders
    "order", "orders", "getOrder", "orderById", "purchaseHistory", "orderHistory",
    "transactions", "getOrders",
    # cart/bag
    "cart", "bag", "bagCount", "getBag", "getCart", "getBasket",
    # wishlist/saved
    "wishlist", "getWishlist", "savedItems", "favorites", "getOnelist",
    "getOnelistItems", "getSharedList",
    # address
    "address", "addresses", "addressBook", "getAddress", "getSavedAddresses",
    # payment
    "paymentMethods", "getPaymentMethods", "savedCards", "wallet",
    # loyalty/rewards
    "loyalty", "rewards", "points", "giftCard", "giftCards", "loyaltyProfile",
    # auth
    "getUserAuthenticators", "authenticators", "sessions",
    # misc
    "notification", "notifications", "inbox", "settings", "preferences",
    "subscription", "subscriptions", "tracking", "shipments",
]

# Common mutation names
MUTATION_FIELDS = [
    "addToCart", "removeFromCart", "updateCart", "checkout",
    "addItemToWishlist", "removeFromWishlist", "createWishlist",
    "updateProfile", "updateAddress", "addAddress", "deleteAddress",
    "addPaymentMethod", "removePaymentMethod",
    "createOrder", "cancelOrder", "returnOrder",
    "redeemGiftCard", "applyPromoCode",
    "updateEmail", "updatePassword", "deleteAccount",
]


def make_request(url: str, payload: dict, headers: dict) -> dict | None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return None
    except Exception:
        return None


def probe_field(url: str, headers: dict, field: str, op_type: str = "query") -> tuple[str, str]:
    """Returns (field, status) where status is EXISTS / MISSING / ERROR / suggestion."""
    payload = {
        "query": f"{op_type} {{ {field} {{ id }} }}",
        "variables": {},
    }
    result = make_request(url, payload, headers)
    if result is None:
        return field, "ERROR"

    if "data" in result and field in result.get("data", {}):
        return field, "EXISTS"

    errors = result.get("errors", [])
    if not errors:
        return field, "EXISTS"

    msg = errors[0].get("message", "")

    if f'Cannot query field "{field}"' in msg:
        # check for suggestions
        if "Did you mean" in msg:
            import re
            suggestions = re.findall(r'"([^"]+)"', msg.split("Did you mean")[1])
            return field, f"MISSING (suggest: {', '.join(suggestions)})"
        return field, "MISSING"

    if "Unknown argument" in msg or "must have a selection" in msg:
        return field, "EXISTS"

    if "provided" in msg.lower() or "required" in msg.lower():
        return field, "EXISTS (needs args)"

    # any other error that didn't say "cannot query field" = field exists but errored
    if f'Cannot query field "{field}"' not in msg:
        return field, f"EXISTS? ({msg[:80]})"

    return field, "MISSING"


def run_enum(url: str, headers: dict, fields: list[str], op_type: str, workers: int, delay: float):
    found = []
    suggestions = []

    print(f"\n[*] Probing {len(fields)} {op_type} fields on {url}")
    print(f"[*] Workers: {workers}  Delay: {delay}s\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe_field, url, headers, f, op_type): f for f in fields}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            field, status = future.result()
            if "EXISTS" in status:
                print(f"  [+] {field:40s} {status}")
                found.append(field)
            elif "suggest" in status.lower():
                print(f"  [~] {field:40s} {status}")
                suggestions.append((field, status))
            # uncomment to see misses:
            # else:
            #     print(f"  [-] {field:40s} {status}")
            if delay > 0:
                time.sleep(delay)

    return found, suggestions


def main():
    parser = argparse.ArgumentParser(description="GraphQL schema enumerator (no introspection needed)")
    parser.add_argument("url", help="GraphQL endpoint URL")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="Key:Value",
                        help="Extra headers (repeat for multiple)")
    parser.add_argument("-c", "--cookie", help="Cookie header value")
    parser.add_argument("-t", "--token", help="Bearer token (adds Authorization: Bearer ...)")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Concurrent workers (default 5)")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between requests in seconds (default 0.1)")
    parser.add_argument("--mutations", action="store_true", help="Also probe mutation fields")
    parser.add_argument("--fields", help="Comma-separated custom field list to probe")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    headers = {
        "Content-Type": "application/json",
        "Origin": args.url.split("/api")[0] if "/api" in args.url else args.url,
        "User-Agent": "Mozilla/5.0 (compatible; bb-tools/1.0)",
    }

    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    fields = args.fields.split(",") if args.fields else QUERY_FIELDS
    all_found = []
    all_suggestions = []

    found, suggestions = run_enum(args.url, headers, fields, "query", args.workers, args.delay)
    all_found.extend(found)
    all_suggestions.extend(suggestions)

    if args.mutations:
        found_m, suggestions_m = run_enum(args.url, headers, MUTATION_FIELDS, "mutation", args.workers, args.delay)
        all_found.extend(found_m)
        all_suggestions.extend(suggestions_m)

    print(f"\n=== RESULTS ===")
    print(f"Found {len(all_found)} live fields:")
    for f in all_found:
        print(f"  {f}")
    if all_suggestions:
        print(f"\nSuggested fields (typos/alternatives):")
        for f, s in all_suggestions:
            print(f"  {f} → {s}")

    if args.output:
        with open(args.output, "w") as fp:
            json.dump({"found": all_found, "suggestions": all_suggestions}, fp, indent=2)
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
