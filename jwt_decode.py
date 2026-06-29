#!/usr/bin/env python3
"""JWT quick-decoder — paste a token, get all claims printed cleanly."""

import sys
import json
import base64
import datetime


def decode_part(part: str) -> dict:
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    decoded = base64.urlsafe_b64decode(part)
    return json.loads(decoded)


def fmt_time(ts):
    try:
        dt = datetime.datetime.utcfromtimestamp(int(ts))
        now = datetime.datetime.utcnow()
        delta = dt - now
        sign = "+" if delta.total_seconds() > 0 else "-"
        secs = abs(int(delta.total_seconds()))
        h, m = divmod(secs // 60, 60)
        rel = f"{sign}{h}h{m:02d}m from now"
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC  ({rel})"
    except Exception:
        return str(ts)


def print_claims(claims: dict):
    time_keys = {"iat", "exp", "nbf", "auth_time"}
    for k, v in claims.items():
        if k in time_keys:
            print(f"  {k:20s} {fmt_time(v)}")
        else:
            print(f"  {k:20s} {v}")


def decode_token(token: str):
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT (need 3 parts)")
        sys.exit(1)

    header = decode_part(parts[0])
    payload = decode_part(parts[1])

    print("\n=== HEADER ===")
    print_claims(header)

    print("\n=== PAYLOAD ===")
    print_claims(payload)

    # highlight key fields
    print("\n=== KEY FIELDS ===")
    for key in ["sub", "uid", "email", "role", "scope", "client_id"]:
        if key in payload:
            print(f"  {key:20s} {payload[key]}")

    exp = payload.get("exp")
    if exp:
        now = datetime.datetime.utcnow().timestamp()
        if exp < now:
            print(f"\n  [!] TOKEN EXPIRED {fmt_time(exp)}")
        else:
            remaining = int(exp - now)
            m, s = divmod(remaining, 60)
            print(f"\n  [+] TOKEN VALID — {m}m{s:02d}s remaining")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        decode_token(sys.argv[1])
    else:
        print("Paste JWT token (or Ctrl+C to quit):")
        try:
            token = input("> ").strip()
            decode_token(token)
        except (KeyboardInterrupt, EOFError):
            print()
