# bb-tools — Bug Bounty Toolkit

Nine tools built for bug bounty hunting — GraphQL IDOR/recon, plus general
web recon (takeovers, CORS, content discovery, security headers).

## Tools

### 1. `jwt_decode.py` — JWT Quick Decoder
Paste any JWT, get all claims with expiry countdown.
```bash
python jwt_decode.py <token>
# or interactive:
python jwt_decode.py
```

### 2. `graphql_enum.py` — GraphQL Schema Enumerator
Probes field names via validation errors. Works even when introspection is disabled.
```bash
# Basic usage
python graphql_enum.py https://shop.lululemon.com/api/graphql \
  --cookie "lll_oidc_token=eyJ..."

# With custom headers + probe mutations too
python graphql_enum.py https://target.com/graphql \
  -H "x-lll-locale: en-US" \
  --cookie "session=abc123" \
  --mutations \
  -o results.json

# Custom field list
python graphql_enum.py https://target.com/graphql \
  --fields "getOrder,getUser,getProfile,getAddress"
```

### 3. `idor_tester.py` — IDOR Session Manager
Store two account sessions, fire queries as either account, auto-detects expiry.
```bash
# Save sessions
python idor_tester.py set a eyJ...TOKEN_A... --cookie lll_oidc_token
python idor_tester.py set b eyJ...TOKEN_B... --cookie lll_oidc_token

# Add extra headers to a session
python idor_tester.py set a eyJ... --cookie lll_oidc_token \
  -H "x-lll-locale: en-US" -H "Origin: https://shop.lululemon.com"

# Check session status
python idor_tester.py show

# Run query as one account
python idor_tester.py run a https://shop.lululemon.com/api/graphql \
  'query { purchaseHistory { orders { id orderId } } }'

# IDOR test: A owns orderId, B tries to access it
python idor_tester.py idor https://shop.lululemon.com/api/graphql \
  'query getOrder($id: String!) { getOrder(id: $id) { id items { sku } } }' \
  --vars-a '{"id":"ORDER-123-A"}' \
  --vars-b '{"id":"ORDER-123-A"}'

# Swap: run same query/vars but with B's session
python idor_tester.py swap https://shop.lululemon.com/api/graphql \
  'query { purchaseHistory { orders { orderId } } }'
```

### 4. `bb_recon.py` — Bug Bounty Recon
Finds GraphQL endpoints, detects WAF, mines JS bundles for operation names.
```bash
# Basic recon
python bb_recon.py shop.lululemon.com

# Full scan: endpoints + CORS + JS mining
python bb_recon.py shop.lululemon.com --js --cors -o lululemon_recon.json

# HTTP target
python bb_recon.py target.com --http
```

### 5. `ssrf_webhook_tester.py` — Webhook SSRF Prober
Spins up a webhook.site catcher, fires internal/cloud-metadata payloads at a webhook-creation endpoint, confirms live outbound delivery, cross-checks source IPs against a target's published IP allowlist.
```bash
python ssrf_webhook_tester.py catcher
python ssrf_webhook_tester.py probe https://target.com/api/v2/webhooks --catcher-url <url>
python ssrf_webhook_tester.py check <catcher-id>
python ssrf_webhook_tester.py verify-ips <catcher-id> https://target.com/api/v2/public-ip-list
python ssrf_webhook_tester.py full https://target.com/api/v2/webhooks   # one-shot: catcher + probe + check
```

### 6. `subdomain_takeover.py` — Subdomain Takeover Checker
Finds dangling CNAMEs pointing at unclaimed third-party services (GitHub Pages, Heroku, S3, Azure, Shopify, Netlify, etc.) via `dig` + provider error-page fingerprints.
```bash
python subdomain_takeover.py old-blog.target.com
python subdomain_takeover.py -i subdomains.txt -o takeover_results.json
```

### 7. `cors_scanner.py` — CORS Misconfiguration Scanner
Sends a random "evil" Origin and the `null` origin at each URL, flags reflected/wildcard ACAO combined with `Access-Control-Allow-Credentials: true`.
```bash
python cors_scanner.py https://api.target.com/v1/data
python cors_scanner.py -i endpoints.txt -o cors_results.json
```

### 8. `content_discovery.py` — Content/Directory Discovery
ffuf/dirsearch-style path brute forcer with soft-404 baseline detection to cut false positives.
```bash
python content_discovery.py https://target.com
python content_discovery.py https://target.com -w custom_wordlist.txt -o found.json
```

### 9. `security_headers.py` — Security Headers Scanner
Checks for missing/weak HSTS, CSP, X-Frame-Options, etc. and cookie flags (HttpOnly/Secure/SameSite) across one or more URLs.
```bash
python security_headers.py https://target.com
python security_headers.py -i endpoints.txt -o headers_results.json
```

## Workflow for IDOR hunting

```
1. python bb_recon.py target.com --js          # find endpoint + operation names
2. python jwt_decode.py <token>                 # check token before it expires
3. python graphql_enum.py <url> -c <cookie>     # map live schema fields
4. python idor_tester.py set a <token-a>        # save Account A
5. python idor_tester.py set b <token-b>        # save Account B
6. python idor_tester.py idor <url> <query> \   # run IDOR test
     --vars-a '{"id":"A_ID"}' \
     --vars-b '{"id":"A_ID"}'                   # B uses A's ID
```

## Workflow for general web recon

```
1. python recon.py target.com --all               # (Pentest-tools) subdomains + ports + tech
2. python subdomain_takeover.py -i subdomains.txt  # check every found subdomain for dangling CNAMEs
3. python content_discovery.py https://target.com  # hidden paths, backups, debug endpoints
4. python security_headers.py https://target.com   # missing HSTS/CSP/cookie flags
5. python cors_scanner.py https://api.target.com    # CORS misconfig on any API endpoints found
6. python ssrf_webhook_tester.py full <webhook-endpoint>  # if a webhook-config feature exists
```
