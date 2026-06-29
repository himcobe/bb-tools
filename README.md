# bb-tools — Bug Bounty Toolkit

Four tools built for GraphQL bug bounty hunting, especially P1/P2 IDOR and recon.

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
