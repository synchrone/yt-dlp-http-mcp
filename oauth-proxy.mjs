import { createServer, request as httpRequest } from 'node:http';
import { spawn } from 'node:child_process';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

const PORT = parseInt(process.env.PORT || '8000');
const INTERNAL_PORT = 8001;
const CLIENT_ID = process.env.MCP_CLIENT_ID;
const CLIENT_SECRET = process.env.MCP_CLIENT_SECRET;
const STATIC_BASE_URL = process.env.MCP_BASE_URL || '';
const DOWNLOAD_URL_PREFIX = process.env.DOWNLOAD_URL_PREFIX || '';
const DOWNLOAD_DIR = process.env.DOWNLOAD_DIR || '/root/Downloads';
const TOKEN_SECRET = process.env.MCP_TOKEN_SECRET || CLIENT_SECRET;
const ACCESS_TOKEN_TTL = parseInt(process.env.ACCESS_TOKEN_TTL || '86400');
const REFRESH_TOKEN_TTL = parseInt(process.env.REFRESH_TOKEN_TTL || String(90 * 86400));

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('MCP_CLIENT_ID and MCP_CLIENT_SECRET must be set');
  process.exit(1);
}

const codes = new Map();   // code -> { redirectUri, codeChallenge, codeChallengeMethod, expiresAt }

const gen = () => randomBytes(32).toString('hex');

const mac = (body) => createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');

function signToken(typ, ttl) {
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const body = Buffer.from(JSON.stringify({ typ, exp, jti: randomBytes(8).toString('hex') })).toString('base64url');
  return `${body}.${mac(body)}`;
}

function verifyToken(token, typ) {
  const [body, sig] = (token || '').split('.');
  if (!body || !sig) return false;
  const expected = Buffer.from(mac(body));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return false;
  try {
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString());
    return claims.typ === typ && claims.exp > Date.now() / 1000;
  } catch {
    return false;
  }
}

function issueTokens(res) {
  return json(res, 200, {
    access_token: signToken('access', ACCESS_TOKEN_TTL),
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    refresh_token: signToken('refresh', REFRESH_TOKEN_TTL),
  });
}

// --- supergateway child process ---
const child = spawn('supergateway', [
  '--stdio', 'yt-dlp-mcp',
  '--outputTransport', 'streamableHttp',
  '--port', String(INTERNAL_PORT),
  '--stateful',
  '--cors',
  '--healthEndpoint', '/healthz',
], { stdio: 'inherit' });

child.on('exit', (code) => {
  console.error(`supergateway exited with code ${code}`);
  process.exit(code || 1);
});

// --- helpers ---
function rewriteDownloadPaths(buf) {
  if (!DOWNLOAD_URL_PREFIX) return buf;
  return buf.replaceAll(DOWNLOAD_DIR, DOWNLOAD_URL_PREFIX);
}

function proxy(req, res) {
  const opts = {
    hostname: '127.0.0.1',
    port: INTERNAL_PORT,
    path: req.url,
    method: req.method,
    headers: { ...req.headers, host: `127.0.0.1:${INTERNAL_PORT}` },
  };
  delete opts.headers.authorization;

  const p = httpRequest(opts, (pRes) => {
    const isSSE = pRes.headers['content-type']?.includes('text/event-stream');
    // Strip content-length when rewriting — length may change
    const headers = { ...pRes.headers };
    if (DOWNLOAD_URL_PREFIX) delete headers['content-length'];
    res.writeHead(pRes.statusCode, headers);

    if (isSSE) {
      res.flushHeaders();
      pRes.on('data', (chunk) => {
        res.write(rewriteDownloadPaths(chunk.toString()));
        res.flushHeaders?.();
      });
      pRes.on('end', () => res.end());
    } else if (DOWNLOAD_URL_PREFIX) {
      const chunks = [];
      pRes.on('data', (chunk) => chunks.push(chunk));
      pRes.on('end', () => {
        res.end(rewriteDownloadPaths(Buffer.concat(chunks).toString()));
      });
    } else {
      pRes.pipe(res);
    }
  });
  p.on('error', () => {
    if (!res.headersSent) { res.writeHead(502); res.end('Bad Gateway'); }
  });
  // When client disconnects, tear down the proxied request
  res.on('close', () => { if (!res.writableFinished) p.destroy(); });
  req.pipe(p);
}

function parseForm(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => b += c);
    req.on('end', () => resolve(new URLSearchParams(b)));
  });
}

function extractClientCredentials(req, body) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Basic ')) {
    const [id, secret] = Buffer.from(authHeader.slice(6), 'base64').toString().split(':');
    return { clientId: id, clientSecret: secret };
  }
  return { clientId: body.get('client_id'), clientSecret: body.get('client_secret') };
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function baseUrl(req) {
  if (STATIC_BASE_URL) return STATIC_BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

// --- server ---
const server = createServer(async (req, res) => {
  const base = baseUrl(req);
  const url = new URL(req.url, base);

  const start = Date.now();
  const origEnd = res.end.bind(res);
  res.end = (...args) => {
    console.log(`${req.method} ${url.pathname} ${res.statusCode} ${Date.now() - start}ms${res.logNote ? ` ${res.logNote}` : ''}`);
    return origEnd(...args);
  };

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // Protected resource metadata (RFC 9728)
  if (url.pathname === '/.well-known/oauth-protected-resource') {
    return json(res, 200, {
      resource: `${base}/mcp`,
      authorization_servers: [base],
      bearer_methods_supported: ['header'],
    });
  }

  // OAuth discovery
  if (url.pathname === '/.well-known/oauth-authorization-server') {
    return json(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    });
  }

  // Authorization endpoint — auto-approves if client_id matches
  if (url.pathname === '/authorize' && req.method === 'GET') {
    const clientId = url.searchParams.get('client_id');
    const redirectUri = url.searchParams.get('redirect_uri');
    const state = url.searchParams.get('state');
    const codeChallenge = url.searchParams.get('code_challenge');
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') || 'plain';

    if (clientId !== CLIENT_ID) return json(res, 400, { error: 'invalid_client' });

    const code = gen();
    codes.set(code, { redirectUri, codeChallenge, codeChallengeMethod, expiresAt: Date.now() + 600_000 });

    const redirect = new URL(redirectUri);
    redirect.searchParams.set('code', code);
    if (state) redirect.searchParams.set('state', state);
    res.writeHead(302, { Location: redirect.toString() });
    return res.end();
  }

  // Token endpoint
  if (url.pathname === '/token' && req.method === 'POST') {
    const body = await parseForm(req);
    const { clientId, clientSecret } = extractClientCredentials(req, body);

    if (clientId !== CLIENT_ID || clientSecret !== CLIENT_SECRET)
      return json(res, 401, { error: 'invalid_client' });

    if (body.get('grant_type') === 'refresh_token') {
      if (!verifyToken(body.get('refresh_token'), 'refresh'))
        return json(res, 400, { error: 'invalid_grant' });
      return issueTokens(res);
    }

    const code = body.get('code');
    if (body.get('grant_type') !== 'authorization_code' || !codes.has(code))
      return json(res, 400, { error: 'invalid_grant' });

    const stored = codes.get(code);
    codes.delete(code);

    if (stored.expiresAt < Date.now())
      return json(res, 400, { error: 'invalid_grant' });

    // PKCE verification
    if (stored.codeChallenge) {
      const verifier = body.get('code_verifier') || '';
      const ok = stored.codeChallengeMethod === 'S256'
        ? createHash('sha256').update(verifier).digest('base64url') === stored.codeChallenge
        : verifier === stored.codeChallenge;
      if (!ok) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE failed' });
    }

    return issueTokens(res);
  }

  // Health — no auth
  if (url.pathname === '/healthz') return proxy(req, res);

  // MCP — require bearer token
  if (url.pathname === '/mcp') {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!verifyToken(token, 'access')) {
      const err = token ? 'error="invalid_token", ' : '';
      res.logNote = token ? 'invalid_token' : 'no_token';
      res.setHeader('WWW-Authenticate', `Bearer ${err}resource_metadata="${base}/.well-known/oauth-protected-resource"`);
      return json(res, 401, { error: 'unauthorized' });
    }
    return proxy(req, res);
  }

  res.writeHead(404); res.end('Not Found');
});

setTimeout(() => {
  server.listen(PORT, () => {
    const display = STATIC_BASE_URL || `http://localhost:${PORT}`;
    console.log(`OAuth MCP proxy listening on ${display}`);
    console.log(`MCP endpoint: ${display}/mcp`);
  });
}, 1000);
