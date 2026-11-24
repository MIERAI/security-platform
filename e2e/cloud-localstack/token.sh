#!/bin/sh
# The workload's identity token, fetched from the local OIDC issuer at each use and printed (never stored):
#   token.sh <issuer base url> <issuer id> <audience>
# In production this is a projected service-account token file or the CI system's OIDC endpoint.
curl -fsS -X POST "$1/$2/token" --data-urlencode grant_type=client_credentials --data-urlencode client_id=security-platform \
  --data-urlencode client_secret=x --data-urlencode "scope=$3" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
