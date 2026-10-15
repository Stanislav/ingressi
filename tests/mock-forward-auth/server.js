/**
 * Mock forward-auth server for the generic forward-auth functional tests
 * (tests/e2e/functional/forward-auth-generic.spec.ts).
 *
 * Mimics the two Authelia authorization behaviors plus a "generic" provider
 * that always redirects:
 *
 *  - /api/authz/forward-auth  — Authelia-style: 200 + Remote-* identity
 *    headers for a valid session cookie; otherwise 302 to the portal for
 *    browser-shaped requests (Accept contains text/html, no X-Requested-With)
 *    and 401 for API-shaped requests.
 *  - /api/always-redirect     — generic provider whose single endpoint always
 *    302-redirects unauthenticated callers (valid sessions still get 200 + headers).
 *  - /outpost.goauthentik.io/ — an Authentik outpost: the Caddy forward-auth
 *    endpoint (/outpost.goauthentik.io/auth/caddy) answers 200 + X-Authentik-*
 *    headers for a valid session cookie, else 302 to the outpost's start page
 *    for browser-shaped requests and 401 for API-shaped ones; every other path
 *    under the prefix answers "outpost-ok" (the outpost route Caddy proxies).
 *
 * Reachable inside the test docker network as "mock-forward-auth:9091".
 */
/* eslint-disable @typescript-eslint/no-require-imports, no-undef */
const http = require('node:http');

const PORT = 9091;
const PORTAL_URL = 'http://auth-portal.test:9091/';
const VALID_COOKIE = 'authelia_session=valid-session';
const AUTHENTIK_COOKIE = 'authentik_proxy=valid-session';
const OUTPOST_PREFIX = '/outpost.goauthentik.io/';

function identityHeaders() {
  return {
    'Remote-User': 'alice',
    'Remote-Groups': 'admins,users',
    'Remote-Email': 'alice@example.com',
    'Remote-Name': 'Alice Example',
    'Remote-IP': '10.0.0.1'
  };
}

function authentikHeaders() {
  return {
    'X-Authentik-Username': 'alice',
    'X-Authentik-Groups': 'admins|users',
    'X-Authentik-Email': 'alice@example.com',
    'X-Authentik-Name': 'Alice Example',
    'X-Authentik-Uid': 'alice-uid'
  };
}

function isBrowserRequest(req) {
  const accept = req.headers['accept'] || '';
  const xhr = req.headers['x-requested-with'] || '';
  return accept.includes('text/html') && xhr.length === 0;
}

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body || '');
}

function handleAuth(req, res, mode) {
  const cookie = req.headers['cookie'] || '';
  if (cookie.includes(VALID_COOKIE)) {
    send(res, 200, identityHeaders());
    return;
  }

  if (mode === 'always-redirect') {
    const target = `${PORTAL_URL}?rd=${encodeURIComponent(`http://${req.headers['x-forwarded-host'] || 'unknown'}${req.headers['x-forwarded-uri'] || '/'}`)}`;
    send(res, 302, { Location: target }, 'Redirecting to portal');
    return;
  }

  if (isBrowserRequest(req)) {
    const target = `${PORTAL_URL}?rd=${encodeURIComponent(`http://${req.headers['x-forwarded-host'] || 'unknown'}${req.headers['x-forwarded-uri'] || '/'}`)}`;
    send(res, 302, { Location: target }, 'Redirecting to portal');
    return;
  }

  send(res, 401, { 'Content-Type': 'application/json' }, JSON.stringify({ status: '401', message: 'Unauthenticated' }));
}

function handleAuthentik(req, res) {
  const cookie = req.headers['cookie'] || '';
  if (cookie.includes(AUTHENTIK_COOKIE)) {
    send(res, 200, authentikHeaders());
    return;
  }
  if (isBrowserRequest(req)) {
    const target = `${PORTAL_URL}outpost.goauthentik.io/start?rd=${encodeURIComponent(`http://${req.headers['x-forwarded-host'] || 'unknown'}${req.headers['x-forwarded-uri'] || '/'}`)}`;
    send(res, 302, { Location: target }, 'Redirecting to the outpost');
    return;
  }
  send(res, 401, { 'Content-Type': 'application/json' }, JSON.stringify({ status: '401', message: 'Unauthenticated' }));
}

const server = http.createServer((req, res) => {
  const path = (req.url || '/').split('?')[0];
  if (path === `${OUTPOST_PREFIX}auth/caddy`) {
    handleAuthentik(req, res);
    return;
  }
  if (path.startsWith(OUTPOST_PREFIX)) {
    send(res, 200, { 'Content-Type': 'text/plain' }, 'outpost-ok');
    return;
  }
  if (path === '/api/authz/forward-auth') {
    handleAuth(req, res, 'authelia');
    return;
  }
  if (path === '/api/always-redirect') {
    handleAuth(req, res, 'always-redirect');
    return;
  }
  if (path === '/health') {
    send(res, 200, { 'Content-Type': 'application/json' }, JSON.stringify({ status: 'ok' }));
    return;
  }
  send(res, 404, {}, 'not found');
});

server.listen(PORT, () => {
  console.log(`mock-forward-auth listening on :${PORT}`);
});
