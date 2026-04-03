#!/usr/bin/env bash
set -euo pipefail

PORT=8099
CONTAINER=yt-dlp-mcp-test
CLIENT_ID=test-client
CLIENT_SECRET=test-secret
BASE=http://localhost:$PORT

cleanup() { docker rm -f $CONTAINER &>/dev/null || true; }
trap cleanup EXIT
cleanup

echo "=== Building image ==="
docker build -t yt-dlp-http-mcp . >/dev/null 2>&1

echo "=== Starting container ==="
docker run -d --name $CONTAINER -p $PORT:8000 \
  -e MCP_CLIENT_ID=$CLIENT_ID \
  -e MCP_CLIENT_SECRET=$CLIENT_SECRET \
  yt-dlp-http-mcp >/dev/null

# Wait for server to be ready
for i in $(seq 1 30); do
  if curl -sf $BASE/healthz &>/dev/null; then break; fi
  sleep 0.5
done

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "PASS: $1"; }

# --- Health ---
curl -sf $BASE/healthz >/dev/null && pass "healthz" || fail "healthz"

# --- OAuth discovery ---
DISCOVERY=$(curl -sf $BASE/.well-known/oauth-authorization-server)
echo "$DISCOVERY" | grep -q '"authorization_endpoint"' && pass "oauth discovery" || fail "oauth discovery"

# --- OAuth discovery respects X-Forwarded headers ---
FWD=$(curl -sf $BASE/.well-known/oauth-authorization-server \
  -H "X-Forwarded-Proto: https" -H "X-Forwarded-Host: mcp.example.com")
echo "$FWD" | grep -q '"https://mcp.example.com/authorize"' && pass "forwarded headers" || fail "forwarded headers"

# --- Unauthenticated MCP is rejected ---
STATUS=$(curl -so /dev/null -w '%{http_code}' -X POST $BASE/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
[ "$STATUS" = "401" ] && pass "unauthenticated rejected" || fail "unauthenticated rejected (got $STATUS)"

# --- Invalid client_id at /authorize ---
STATUS=$(curl -so /dev/null -w '%{http_code}' "$BASE/authorize?client_id=wrong&redirect_uri=http://localhost/cb&response_type=code")
[ "$STATUS" = "400" ] && pass "bad client_id rejected" || fail "bad client_id rejected (got $STATUS)"

# --- Full OAuth flow ---
REDIR=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost/cb&state=s1&response_type=code&code_challenge=testverifier&code_challenge_method=plain")
CODE=$(echo "$REDIR" | grep -oP 'code=\K[^&]+')
[ -n "$CODE" ] && pass "authorization code issued" || fail "authorization code not in redirect: $REDIR"
echo "$REDIR" | grep -q 'state=s1' && pass "state preserved" || fail "state not preserved"

# --- Token exchange ---
TOKEN_RESP=$(curl -sf -X POST $BASE/token \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=http://localhost/cb&code_verifier=testverifier")
TOKEN=$(echo "$TOKEN_RESP" | grep -oP '"access_token":"\K[^"]+')
[ -n "$TOKEN" ] && pass "token exchange" || fail "token exchange: $TOKEN_RESP"

# --- Token exchange with Basic auth ---
REDIR2=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost/cb&response_type=code&code_challenge=v2&code_challenge_method=plain")
CODE2=$(echo "$REDIR2" | grep -oP 'code=\K[^&]+')
BASIC=$(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)
TOKEN_RESP2=$(curl -sf -X POST $BASE/token \
  -H "Authorization: Basic $BASIC" \
  -d "grant_type=authorization_code&code=$CODE2&redirect_uri=http://localhost/cb&code_verifier=v2")
echo "$TOKEN_RESP2" | grep -q '"access_token"' && pass "token via basic auth" || fail "token via basic auth: $TOKEN_RESP2"

# --- Wrong client_secret at /token ---
REDIR3=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost/cb&response_type=code")
CODE3=$(echo "$REDIR3" | grep -oP 'code=\K[^&]+')
STATUS=$(curl -so /dev/null -w '%{http_code}' -X POST $BASE/token \
  -d "grant_type=authorization_code&code=$CODE3&client_id=$CLIENT_ID&client_secret=wrong")
[ "$STATUS" = "401" ] && pass "bad secret rejected" || fail "bad secret rejected (got $STATUS)"

# --- PKCE S256 ---
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
REDIR4=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost/cb&response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256")
CODE4=$(echo "$REDIR4" | grep -oP 'code=\K[^&]+')
TOKEN_RESP4=$(curl -sf -X POST $BASE/token \
  -d "grant_type=authorization_code&code=$CODE4&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=http://localhost/cb&code_verifier=$VERIFIER")
echo "$TOKEN_RESP4" | grep -q '"access_token"' && pass "PKCE S256" || fail "PKCE S256: $TOKEN_RESP4"

# --- Code replay rejected ---
STATUS=$(curl -so /dev/null -w '%{http_code}' -X POST $BASE/token \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code_verifier=testverifier")
[ "$STATUS" = "400" ] && pass "code replay rejected" || fail "code replay rejected (got $STATUS)"

# --- Authenticated MCP initialize ---
MCP_RESP=$(curl -sf -X POST $BASE/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}')
echo "$MCP_RESP" | grep -q '"yt-dlp-mcp"' && pass "MCP initialize" || fail "MCP initialize: $MCP_RESP"

echo ""
echo "=== All tests passed ==="
