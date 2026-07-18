# bb-tools — Bug Bounty Toolkit

General-purpose recon tools built for bug bounty hunting — JWT inspection, endpoint/WAF
discovery, content discovery, tech fingerprinting, exposed file/secret scanning, and misc
header/redirect checks.

**Looking for the full set?** GraphQL schema enumeration, a two-account IDOR tester, an
SSRF/cloud-metadata webhook prober, subdomain takeover checking, and a CORS scanner are part
of the complete 9-tool [CCypher Recon Toolkit](https://cyphertech7.gumroad.com/l/zlimza) ($24).

## Tools

### 1. `jwt_decode.py` — JWT Quick Decoder
Paste any JWT, get all claims with expiry countdown.
```bash
python jwt_decode.py <token>
# or interactive:
python jwt_decode.py
```

### 2. `bb_recon.py` — Bug Bounty Recon
Finds GraphQL endpoints, detects WAF, mines JS bundles for operation names.
```bash
# Basic recon
python bb_recon.py shop.target.com

# Full scan: endpoints + CORS + JS mining
python bb_recon.py shop.target.com --js --cors -o target_recon.json

# HTTP target
python bb_recon.py target.com --http
```

### 3. `content_discovery.py` — Content/Directory Discovery
ffuf/dirsearch-style path brute forcer with soft-404 baseline detection to cut false positives.
```bash
python content_discovery.py https://target.com
python content_discovery.py https://target.com -w custom_wordlist.txt -o found.json
```

### 4. `security_headers.py` — Security Headers Scanner
Checks for missing/weak HSTS, CSP, X-Frame-Options, etc. and cookie flags (HttpOnly/Secure/SameSite) across one or more URLs.
```bash
python security_headers.py https://target.com
python security_headers.py -i endpoints.txt -o headers_results.json
```

### 5. `tech_fingerprint.py` — Tech Stack Fingerprinter
Identifies framework/CMS/server/CDN from response headers, cookies, and body signatures.
```bash
python tech_fingerprint.py https://target.com
python tech_fingerprint.py -i targets.txt -o fingerprints.json
```

### 6. `exposed_files_scanner.py` — Exposed Files Scanner
Checks for common sensitive files left accessible (`.env`, `.git/config`, backups, API specs), with soft-404 baselining so a custom "200 OK" error page doesn't create false positives.
```bash
python exposed_files_scanner.py https://target.com
python exposed_files_scanner.py https://target.com -o exposed.json
```

### 7. `open_redirect_scanner.py` — Open Redirect Scanner
Tries common redirect-looking parameter names with an external payload and checks whether the response actually sends the browser off-domain (Location header, meta-refresh, or JS `location=`).
```bash
python open_redirect_scanner.py "https://target.com/login?next=/dashboard"
python open_redirect_scanner.py "https://target.com/page" --params redirect,url,next
```

### 8. `clickjacking_checker.py` — Clickjacking Checker
Checks whether a page can be framed — evaluates CSP `frame-ancestors` (which supersedes X-Frame-Options in modern browsers) as well as the legacy header.
```bash
python clickjacking_checker.py https://target.com
python clickjacking_checker.py -i endpoints.txt -o clickjacking.json
```

### 9. `js_secrets_scanner.py` — JS Secrets Scanner
Pulls `<script src>` URLs off a page and regex-hunts the JS for leaked cloud keys, API tokens, Stripe/Slack keys, and private key headers. Matches are masked in output.
```bash
python js_secrets_scanner.py https://target.com
python js_secrets_scanner.py https://target.com/static/bundle.js -o secrets.json
```

## Workflow for general web recon

```
1. python bb_recon.py target.com --js               # find endpoint + operation names
2. python tech_fingerprint.py https://target.com     # ID the stack before you dig further
3. python jwt_decode.py <token>                      # check token before it expires
4. python content_discovery.py https://target.com    # hidden paths, backups, debug endpoints
5. python exposed_files_scanner.py https://target.com # .env, .git, backup files
6. python security_headers.py https://target.com     # missing HSTS/CSP/cookie flags
7. python clickjacking_checker.py https://target.com  # frameable pages
8. python open_redirect_scanner.py "https://target.com/page?next=/x"  # redirect params
9. python js_secrets_scanner.py https://target.com    # leaked keys in JS bundles
```
