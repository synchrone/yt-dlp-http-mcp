# yt-dlp-http-mcp

[yt-dlp-mcp](https://github.com/kevinwatt/yt-dlp-mcp) served over Streamable HTTP (via [supergateway](https://github.com/supercorp-ai/supergateway)) behind a minimal OAuth 2.1 proxy, so it can be added as a remote MCP server in claude.ai, Claude desktop, and Claude Code.

## Run

```bash
docker run -d --name yt-dlp-mcp --restart unless-stopped \
  -p 8000:8000 \
  -e MCP_CLIENT_ID=<pick-an-id> \
  -e MCP_CLIENT_SECRET=<long-random-string> \
  -v /path/to/downloads:/root/Downloads \
  ghcr.io/synchrone/yt-dlp-http-mcp:latest
```

| Env var | Default | Purpose |
|---|---|---|
| `MCP_CLIENT_ID` | required | OAuth client ID clients must present |
| `MCP_CLIENT_SECRET` | required | OAuth client secret; also signs tokens unless `MCP_TOKEN_SECRET` is set |
| `MCP_TOKEN_SECRET` | `MCP_CLIENT_SECRET` | Token signing key. Changing it logs everyone out |
| `ACCESS_TOKEN_TTL` | `86400` (1 day) | Access token lifetime, seconds |
| `REFRESH_TOKEN_TTL` | `7776000` (90 days) | Refresh token lifetime, seconds; each refresh issues a new one |
| `MCP_BASE_URL` | derived from request | Public base URL, e.g. `https://yt.example.com` |
| `DOWNLOAD_DIR` | `/root/Downloads` | Download location inside the container |
| `DOWNLOAD_URL_PREFIX` | unset | If set, replaces `DOWNLOAD_DIR` paths in responses with this URL prefix |
| `PORT` | `8000` | Listen port |

Generate a secret with `openssl rand -hex 32`.

## Reverse proxy

- Serve it over HTTPS; claude.ai requires it.
- Forward `X-Forwarded-Proto` and `X-Forwarded-Host`, or set `MCP_BASE_URL`. Otherwise the OAuth discovery documents advertise `http://localhost:8000` and clients can't log in.
- Don't buffer `/mcp` and allow long read timeouts; it streams responses as server-sent events.

Endpoints:

| Path | Auth | Purpose |
|---|---|---|
| `/mcp` | Bearer token | MCP Streamable HTTP endpoint |
| `/healthz` | none | Health check |
| `/.well-known/oauth-protected-resource` | none | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server` | none | RFC 8414 server metadata |
| `/authorize`, `/token` | client credentials | OAuth flow |

## Connect

### claude.ai / Claude desktop

Settings → Connectors → Add custom connector:

- URL: `https://<your-host>/mcp`
- Advanced settings: OAuth Client ID and Client Secret

The connector is then also available in Claude Code as `claude.ai yt-dlp`.

### Claude Code (direct)

```bash
claude mcp add --transport http yt-dlp https://<your-host>/mcp --client-id <id> --client-secret
```

`--client-secret` prompts for the secret (or reads `MCP_CLIENT_SECRET`).

## Auth model

- There is no login screen: `/authorize` approves any request with the right client ID. The client secret is the real credential, since the token exchange requires it. Anyone with the secret can obtain tokens.
- No dynamic client registration; every client is configured with the ID and secret by hand.
- Access and refresh tokens are HMAC-signed and not stored server-side, so they survive restarts and work across instances sharing the same secret. Clients renew them with the `refresh_token` grant.
- To revoke all sessions, change `MCP_TOKEN_SECRET` (or `MCP_CLIENT_SECRET` if the former is unset).

## Test

```bash
./test.sh
```

Builds the image, runs it, and exercises the OAuth flow, refresh, restart survival, and MCP initialize. Needs Docker and a grep with `-P` (GNU grep).
