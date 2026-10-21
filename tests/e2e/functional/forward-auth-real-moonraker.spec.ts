/**
 * Functional tests: Generic Forward Auth + REAL Moonraker upstream.
 *
 * Uses the real Authelia container as the forward-auth provider and a real
 * Moonraker (Klipper API server, v0.11) as the upstream, mirroring the exact
 * mixed browser + API scenario from issue #188:
 *
 *  - Moonraker enforces its OWN api key (v0.11 stores a per-instance key in
 *    its database; the setup fetches it via a trusted localhost call inside
 *    the container). The X-Api-Key bypass header lets requests skip Ingressi
 *    forward auth, and Moonraker itself rejects keys it does not accept —
 *    proving the bypass-header delegation end-to-end (the negative test
 *    recommended in docs/forward-auth-generic-security-analysis.md).
 *  - Requests without the bypass header are authenticated by real Authelia;
 *    a forwarded, Authelia-authenticated request still gets 401 from
 *    Moonraker unless it also carries Moonraker's key (layered auth).
 *  - Moonraker's WebSocket endpoint upgrades through the bypass path.
 *
 * Domain: mr.auth.test (within the auth.test cookie scope).
 */
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { engineBin } from '../../helpers/engine';
import { httpsGet, wssHandshakeTls } from '../../helpers/https';
import { createSelfSignedServerCertificate } from '../../helpers/certs';
import { autheliaFirstFactor } from '../../helpers/authelia';

const DOMAIN = 'mr.auth.test';
const API = 'http://localhost:3000/api/v1';
const ORIGIN = 'http://localhost:3000';

let hostId: number;
let moonrakerApiKey: string;

/** Fetch Moonraker's runtime API key from a trusted localhost call inside the container. */
function fetchMoonrakerApiKey(): string {
  const out = execFileSync(
    engineBin(),
    [
      'exec', 'moonraker-e2e', '/opt/venv/bin/python', '-c',
      "import urllib.request, json; print(json.load(urllib.request.urlopen('http://127.0.0.1:7125/access/api_key'))['result'])",
    ],
    { encoding: 'utf-8' }
  ).trim();
  expect(out).toMatch(/^[0-9a-f]{32}$/);
  return out;
}

test.describe.serial('Generic Forward Auth — Real Moonraker', () => {
  test('setup: TLS certificate, proxy host, and Moonraker runtime key', async ({ page }) => {
    const serverCert = createSelfSignedServerCertificate(DOMAIN, [DOMAIN]);
    const certRes = await page.request.post(`${API}/certificates`, {
      data: {
        name: 'Real Moonraker Test Cert',
        type: 'imported',
        domainNames: [DOMAIN],
        autoRenew: false,
        certificatePem: serverCert.certificatePem,
        privateKeyPem: serverCert.privateKeyPem,
      },
      headers: { 'Content-Type': 'application/json', 'Origin': ORIGIN },
    });
    expect(certRes.status()).toBe(201);
    const cert = await certRes.json();

    const res = await page.request.post(`${API}/proxy-hosts`, {
      data: {
        name: 'Real Moonraker Host',
        domains: [DOMAIN],
        upstreams: ['moonraker:7125'],
        sslForced: true,
        certificateId: cert.id,
        forwardAuth: {
          enabled: true,
          provider: 'authelia',
          authUpstream: 'http://authelia:9091',
          authEndpoint: '/api/authz/forward-auth',
          apiSplit: true,
          apiBypassHeaders: ['X-Api-Key'],
        },
      },
      headers: { 'Content-Type': 'application/json', 'Origin': ORIGIN },
    });
    expect(res.status()).toBe(201);
    const host = await res.json();
    hostId = host.id;

    // Route ready: unauthenticated requests hit real Authelia and get 401.
    const deadline = Date.now() + 30_000;
    let last = 0;
    while (Date.now() < deadline) {
      try {
        const probe = await httpsGet(DOMAIN, '/server/info');
        last = probe.status;
        if (probe.status === 401) break;
      } catch { /* TLS route not ready */ }
      await new Promise((r) => setTimeout(r, 500));
    }
    expect(last).toBe(401);

    moonrakerApiKey = fetchMoonrakerApiKey();
  });

  test('Authelia-authenticated request reaches real Moonraker (which enforces its own key)', async () => {
    const login = await autheliaFirstFactor('e2euser', 'TestPassword2026!');
    expect(login.status).toBe(200);
    expect(login.sessionCookie).toBeTruthy();

    // Forward auth authenticates the caller and passes the request through to
    // Moonraker — which enforces ITS OWN API key for non-trusted clients and
    // answers 401 with its distinctive JSON error envelope. This is the
    // layered-auth reality of the Moonraker setup from issue #188: browser
    // users log in at the IdP, machine clients use X-Api-Key, and Moonraker
    // remains the authority for its own API.
    const res = await httpsGet(DOMAIN, '/server/info', {}, {
      Cookie: `authelia_session=${login.sessionCookie}`,
    });
    expect(res.status).toBe(401);
    expect(res.body).toContain('"code":401');
    expect(res.body).toContain('moonraker');
  });

  test('X-Api-Key request bypasses forward auth and real Moonraker accepts the key', async () => {
    const res = await httpsGet(DOMAIN, '/server/info', {}, { 'X-Api-Key': moonrakerApiKey });
    expect(res.status).toBe(200);
    expect(res.body).toContain('"result"');
    expect(res.body).toContain('moonraker');
  });

  test('X-Api-Key bypass does not bypass Moonraker: a wrong key is rejected by the upstream', async () => {
    // The bypass header skips Ingressi forward auth entirely — this request never
    // touches Authelia. Moonraker itself must reject the bad key.
    const res = await httpsGet(DOMAIN, '/server/info', {}, { 'X-Api-Key': 'wrong-key' });
    expect(res.status).toBe(401);
    expect(res.body).toContain('"code":401');
  });

  test('Moonraker WebSocket upgrades through the bypass path', async () => {
    const ws = await wssHandshakeTls(DOMAIN, '/websocket', { 'X-Api-Key': moonrakerApiKey });
    expect(ws.statusCode).toBe(101);
    expect(ws.headers['upgrade']).toBe('websocket');
  });

  test('unauthenticated WebSocket handshake gets 401 from real Authelia', async () => {
    const ws = await wssHandshakeTls(DOMAIN, '/websocket');
    expect(ws.statusCode).toBe(401);
  });

  test('cleanup: delete proxy host', async ({ page }) => {
    if (hostId) {
      const res = await page.request.delete(`${API}/proxy-hosts/${hostId}`, {
        headers: { 'Origin': ORIGIN },
      });
      expect(res.status()).toBe(200);
    }
  });
});
