# bb-tools — Bug Bounty Toolkit

General-purpose recon tools built for bug bounty hunting — JWT inspection, endpoint/WAF
discovery, content discovery, and security header auditing.

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

## Workflow for general web recon

```
1. python bb_recon.py target.com --js              # find endpoint + operation names
2. python jwt_decode.py <token>                     # check token before it expires
3. python content_discovery.py https://target.com   # hidden paths, backups, debug endpoints
4. python security_headers.py https://target.com    # missing HSTS/CSP/cookie flags
```
