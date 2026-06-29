#!/usr/bin/env python3
"""
IDOR session manager — stores two accounts, fires any GraphQL query/mutation
as either account, auto-detects token expiry.
"""

import os
import sys
import json
import time
import argparse
import datetime
import base64
import urllib.request
import urllib.error


SESSION_FILE = os.path.join(os.path.dirname(__file__), ".idor_sessions.json")


# ── JWT helpers ──────────────────────────────────────────────────────────────

def decode_jwt_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def token_expires_in(token: str) -> int:
    """Returns seconds until expiry. Negative = already expired."""
    payload = decode_jwt_payload(token)
    exp = payload.get("exp")
    if not exp:
        return 9999
    return int(exp - time.time())


def token_subject(token: str) -> str:
    payload = decode_jwt_payload(token)
    return payload.get("sub") or payload.get("email") or payload.get("uid") or "unknown"


# ── Session storage ───────────────────────────────────────────────────────────

def load_sessions() -> dict:
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            return json.load(f)
    return {"a": {}, "b": {}}


def save_sessions(sessions: dict):
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)
    print(f"[+] Sessions saved to {SESSION_FILE}")


def show_sessions(sessions: dict):
    for acct in ["a", "b"]:
        s = sessions.get(acct, {})
        if not s:
            print(f"  Account {acct.upper()}: not set")
            continue
        token = s.get("token", "")
        remaining = token_expires_in(token)
        sub = token_subject(token)
        status = f"VALID ({remaining//60}m{remaining%60:02d}s left)" if remaining > 0 else f"EXPIRED ({abs(remaining)//60}m ago)"
        print(f"  Account {acct.upper()}: {sub} — {status}")
        if s.get("extra_headers"):
            print(f"    Headers: {s['extra_headers']}")


# ── HTTP ──────────────────────────────────────────────────────────────────────

def make_request(url: str, payload: dict, headers: dict) -> dict | None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def build_headers(session: dict, url: str) -> dict:
    origin = url.split("/api")[0] if "/api" in url else "/".join(url.split("/")[:3])
    headers = {
        "Content-Type": "application/json",
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (compatible; bb-tools/1.0)",
    }
    token = session.get("token", "")
    cookie_name = session.get("cookie_name", "token")
    if cookie_name == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    else:
        headers["Cookie"] = f"{cookie_name}={token}"

    for k, v in session.get("extra_headers", {}).items():
        headers[k] = v

    return headers


# ── IDOR test ─────────────────────────────────────────────────────────────────

def run_query(url: str, session: dict, gql: str, variables: dict, label: str):
    remaining = token_expires_in(session.get("token", ""))
    if remaining < 0:
        print(f"  [!] {label} token EXPIRED ({abs(remaining)//60}m ago) — update it with: python idor_tester.py set {label.lower()}")

    headers = build_headers(session, url)
    payload = {"query": gql, "variables": variables}

    print(f"\n--- {label} ---")
    result = make_request(url, payload, headers)
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("  [!] No response")
    return result


def run_idor_test(url: str, sessions: dict, gql: str, variables_a: dict, variables_b: dict):
    """Run query as Account A, then replay with Account B's session."""
    print(f"\n[*] IDOR TEST on {url}")
    print(f"[*] Query: {gql[:100]}...")

    result_a = run_query(url, sessions["a"], gql, variables_a, "Account A (owner)")
    result_b = run_query(url, sessions["b"], gql, variables_b, "Account B (attacker)")

    print("\n=== ANALYSIS ===")
    if result_b and "errors" not in result_b:
        data_b = result_b.get("data", {})
        if any(v is not None for v in data_b.values()):
            print("  [!!!] POTENTIAL IDOR — Account B received data without errors!")
            print("  Compare outputs above carefully.")
        else:
            print("  [~] Account B got null data (may be blocked or empty)")
    elif result_b and "errors" in result_b:
        err = result_b["errors"][0].get("message", "")
        code = result_b["errors"][0].get("extensions", {}).get("statusCode", "")
        print(f"  [-] Account B blocked: {code} — {err[:100]}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDOR session manager for bug bounty")
    sub = parser.add_subparsers(dest="cmd")

    # set account
    p_set = sub.add_parser("set", help="Save a session token for account A or B")
    p_set.add_argument("account", choices=["a", "b"], help="Account slot")
    p_set.add_argument("token", help="JWT or session token value")
    p_set.add_argument("--cookie", default="token", help="Cookie name (default: token). Use 'bearer' for Authorization header")
    p_set.add_argument("-H", "--header", action="append", default=[], metavar="Key:Value",
                       help="Extra headers for this account")

    # show sessions
    sub.add_parser("show", help="Show saved sessions and expiry")

    # run query as one account
    p_run = sub.add_parser("run", help="Run a GraphQL query as account A or B")
    p_run.add_argument("account", choices=["a", "b"])
    p_run.add_argument("url", help="GraphQL endpoint")
    p_run.add_argument("query", help="GraphQL query string")
    p_run.add_argument("-v", "--variables", default="{}", help="JSON variables")

    # idor test
    p_idor = sub.add_parser("idor", help="Run IDOR test: A owns resource, B tries to access it")
    p_idor.add_argument("url", help="GraphQL endpoint")
    p_idor.add_argument("query", help="GraphQL query/mutation")
    p_idor.add_argument("--vars-a", default="{}", help="Variables for Account A (owner)")
    p_idor.add_argument("--vars-b", default="{}", help="Variables for Account B (attacker, with A's IDs swapped in)")

    # swap: run A's query with B's session
    p_swap = sub.add_parser("swap", help="Run exact same query/vars but swap to account B's session")
    p_swap.add_argument("url")
    p_swap.add_argument("query")
    p_swap.add_argument("-v", "--variables", default="{}")

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        return

    sessions = load_sessions()

    if args.cmd == "set":
        extra = {}
        for h in args.header:
            k, _, v = h.partition(":")
            extra[k.strip()] = v.strip()
        sessions[args.account] = {
            "token": args.token,
            "cookie_name": args.cookie,
            "extra_headers": extra,
        }
        save_sessions(sessions)
        sub_id = token_subject(args.token)
        remaining = token_expires_in(args.token)
        status = f"valid {remaining//60}m{remaining%60:02d}s" if remaining > 0 else "EXPIRED"
        print(f"[+] Account {args.account.upper()} set: {sub_id} ({status})")

    elif args.cmd == "show":
        print("\n=== SESSIONS ===")
        show_sessions(sessions)

    elif args.cmd == "run":
        if not sessions.get(args.account):
            print(f"[!] Account {args.account.upper()} not set. Run: python idor_tester.py set {args.account} <token>")
            sys.exit(1)
        variables = json.loads(args.variables)
        run_query(args.url, sessions[args.account], args.query, variables, f"Account {args.account.upper()}")

    elif args.cmd == "idor":
        for acct in ["a", "b"]:
            if not sessions.get(acct):
                print(f"[!] Account {acct.upper()} not set.")
                sys.exit(1)
        vars_a = json.loads(args.vars_a)
        vars_b = json.loads(args.vars_b)
        run_idor_test(args.url, sessions, args.query, vars_a, vars_b)

    elif args.cmd == "swap":
        for acct in ["a", "b"]:
            if not sessions.get(acct):
                print(f"[!] Account {acct.upper()} not set.")
                sys.exit(1)
        variables = json.loads(args.variables)
        print("[*] Running as Account A first...")
        run_query(args.url, sessions["a"], args.query, variables, "Account A")
        print("\n[*] Swapping to Account B session (same query/vars)...")
        run_query(args.url, sessions["b"], args.query, variables, "Account B")


if __name__ == "__main__":
    main()
