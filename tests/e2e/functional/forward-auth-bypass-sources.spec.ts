/**
 * Functional tests: addresses that skip sign-in, through the real Caddy, for
 * the built-in sign-in, Authentik (a mock outpost) and generic forward auth
 * (a mock Authelia-style server).
 *
 * The test client reaches Caddy from the address of the Docker bridge (private).
 * The spec learns it from the X-Forwarded-For Caddy sends upstream, so it can
 * list it exactly, and uses trusted proxies plus X-Forwarded-For (or a header
 * of its own) to appear as any other address.
 *
 * It checks, for every provider:
 *  - a client in the list reaches the app without being asked, a client that
 *    is not is asked exactly as before, and a session still works;
 *  - the address is the one Caddy works out: a forged X-Forwarded-For counts
 *    only behind a trusted proxy, strict parsing reads the right entry, a
 *    header of the administrator's choice replaces X-Forwarded-For, IPv6 works;
 *  - the list covers paths the way the sign-in does (the whole host, all but
 *    some paths, only some paths) and the host's location rules;
 *  - only the sign-in is skipped: path blocks, the WAF and access lists still
 *    apply, and identity headers a client forges never reach the app;
 *  - the REST API refuses bad entries and stores nothing.
 *
 * Domains: func-bsrc-<provider>-<kind>.test, func-bsrc-open.test
 */
import { resolve } from 'node:path';
import { test, expect, request as playwrightRequest, type APIRequestContext } from '@playwright/test';
import { httpGet, waitForRoute, type HttpResponse } from '../../helpers/http';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const BROWSER_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
const PORTAL_PREFIX = 'http://auth-portal.test:9091/';
const UPSTREAM = 'whoami-server:80';
const OPEN_DOMAIN = 'func-bsrc-open.test';
const THROUGH = 'Hostname:';

type Mode = 'full' | 'excluded' | 'protected';

interface Provider {
  id: 'ingressi' | 'generic' | 'authentik';
  label: string;
  field: 'ingressiForwardAuth' | 'forwardAuth' | 'authentik';
  /** The sign-in settings of a host with these addresses. */
  config(sources: string[], mode: Mode): Record<string, unknown>;
  /** What a client that is asked gets (a browser request). */
  expectAsked(res: HttpResponse): void;
  /** A request the provider's check accepts, and the header it then sets, or null when there is none. */
  session: { headers: Record<string, string>; identity: string } | null;
  /** Identity headers a client could forge. */
  forged: Record<string, string>;
}

const PATHS: Record<Mode, Record<string, unknown>> = {
  full: {},
  excluded: { excluded: ['/public/*'] },
  protected: { protected: ['/admin/*'] },
};

const PROVIDERS: Provider[] = [
  {
    id: 'ingressi',
    label: 'Built-in sign-in',
    field: 'ingressiForwardAuth',
    config: (sources, mode) => ({
      enabled: true,
      ...(PATHS[mode].excluded ? { excluded_paths: PATHS[mode].excluded } : {}),
      ...(PATHS[mode].protected ? { protected_paths: PATHS[mode].protected } : {}),
      bypass_sources: sources,
    }),
    expectAsked: (res) => {
      expect(res.status).toBe(302);
      expect(String(res.headers['location'])).toContain('/portal?rd=');
      expect(res.body).not.toContain(THROUGH);
    },
    session: null,
    forged: { 'X-Ingressi-User': 'mallory', 'X-Ingressi-Groups': 'admins', 'X-CPM-User': 'mallory' },
  },
  {
    id: 'generic',
    label: 'Generic forward auth',
    field: 'forwardAuth',
    config: (sources, mode) => ({
      enabled: true,
      provider: 'authelia',
      authUpstream: 'http://mock-forward-auth:9091',
      authEndpoint: '/api/authz/forward-auth',
      ...(PATHS[mode].excluded ? { excludedPaths: PATHS[mode].excluded } : {}),
      ...(PATHS[mode].protected ? { protectedPaths: PATHS[mode].protected } : {}),
      bypassSources: sources,
    }),
    expectAsked: (res) => {
      expect(res.status).toBe(302);
      expect(String(res.headers['location'])).toContain(PORTAL_PREFIX);
      expect(res.body).not.toContain(THROUGH);
    },
    session: { headers: { Cookie: 'authelia_session=valid-session' }, identity: 'Remote-User: alice' },
    forged: { 'Remote-User': 'mallory', 'Remote-Groups': 'admins' },
  },
  {
    id: 'authentik',
    label: 'Authentik',
    field: 'authentik',
    config: (sources, mode) => ({
      enabled: true,
      outpostDomain: 'outpost.goauthentik.io',
      outpostUpstream: 'http://mock-forward-auth:9091',
      ...(PATHS[mode].excluded ? { excludedPaths: PATHS[mode].excluded } : {}),
      ...(PATHS[mode].protected ? { protectedPaths: PATHS[mode].protected } : {}),
      bypassSources: sources,
    }),
    expectAsked: (res) => {
      expect(res.status).toBe(302);
      expect(String(res.headers['location'])).toContain('/outpost.goauthentik.io/start');
      expect(res.body).not.toContain(THROUGH);
    },
    session: { headers: { Cookie: 'authentik_proxy=valid-session' }, identity: 'X-Authentik-Username: alice' },
    forged: { 'X-Authentik-Username': 'mallory', 'X-Authentik-Groups': 'admins' },
  },
];

interface Host {
  id: number;
  domain: string;
  provider: Provider;
  mode: Mode;
  kind: string;
}

let api: APIRequestContext;
let peer = '';
let peerNetwork = '';
let aclId: number | null = null;
let originalTrustedProxies: Record<string, unknown> = { ranges: [] };
const created: number[] = [];
const hosts: Record<string, Host> = {};

const probe = (domain: string, path = '/', headers: Record<string, string> = {}) =>
  httpGet(domain, path, { Accept: BROWSER_ACCEPT, ...headers });

async function eventually(check: () => Promise<void>, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await check();
      return;
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

const expectThrough = (res: HttpResponse, marker = THROUGH) => {
  expect(res.status).toBe(200);
  expect(res.body).toContain(marker);
};

async function createHost(
  provider: Provider,
  kind: string,
  mode: Mode,
  sources: string[],
  extra: Record<string, unknown> = {}
): Promise<Host> {
  const domain = `func-bsrc-${provider.id}-${kind}.test`;
  const res = await api.post(`${API}/proxy-hosts`, {
    headers: HEADERS,
    data: {
      name: `Bypass ${provider.label} ${kind}`,
      domains: [domain],
      upstreams: [UPSTREAM],
      sslForced: false,
      [provider.field]: provider.config(sources, mode),
      ...extra,
    },
  });
  expect(res.status(), await res.text()).toBe(201);
  const id = ((await res.json()) as { id: number }).id;
  created.push(id);
  const host = { id, domain, provider, mode, kind };
  hosts[`${provider.id}:${kind}`] = host;
  return host;
}

async function setSources(host: Host, sources: string[]): Promise<void> {
  const res = await api.put(`${API}/proxy-hosts/${host.id}`, { headers: HEADERS, data: { [host.provider.field]: host.provider.config(sources, host.mode) } });
  expect(res.status(), await res.text()).toBe(200);
}

async function setTrustedProxies(settings: Record<string, unknown>): Promise<void> {
  const res = await api.put(`${API}/settings/trusted-proxies`, { headers: HEADERS, data: settings });
  expect(res.status(), await res.text()).toBe(200);
}

const full = (provider: Provider) => hosts[`${provider.id}:full`];

test.describe.serial('Addresses that skip sign-in', () => {
  test.beforeAll(async () => {
    test.setTimeout(300_000);
    api = await playwrightRequest.newContext({ storageState: resolve(__dirname, '../../.auth/admin.json') });
    const settings = await api.get(`${API}/settings/trusted-proxies`);
    // Unset, the settings read as nothing: put back as an empty list, which is what the route accepts.
    if (settings.ok()) originalTrustedProxies = { ranges: [], ...(((await settings.json()) as Record<string, unknown> | null) ?? {}) };

    // An open host, to learn the address Caddy sees the test client from.
    const open = await api.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'Bypass open', domains: [OPEN_DOMAIN], upstreams: [UPSTREAM], sslForced: false },
    });
    expect(open.status(), await open.text()).toBe(201);
    created.push(((await open.json()) as { id: number }).id);
    await waitForRoute(OPEN_DOMAIN);
    let seen = '';
    await eventually(async () => {
      seen = (await httpGet(OPEN_DOMAIN, '/')).body.match(/^X-Forwarded-For: (.+)$/im)?.[1]?.trim() ?? '';
      expect(seen, 'the upstream shows the address Caddy sees the client from').toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    });
    peer = seen;
    peerNetwork = `${seen.split('.').slice(0, 3).join('.')}.0/24`;

    // The list of every host starts with an address nobody here has.
    for (const provider of PROVIDERS) {
      await createHost(provider, 'full', 'full', ['203.0.113.0/24']);
      await createHost(provider, 'excluded', 'excluded', ['203.0.113.0/24']);
      await createHost(provider, 'protected', 'protected', ['203.0.113.0/24']);
      await createHost(provider, 'rich', 'full', ['203.0.113.0/24'], {
        locationRules: [{ path: '/api/*', upstreams: ['echo-server-2:8080'] }],
        pathBlocks: [{ path: '/blocked/*', status: 403, body: 'blocked-by-host' }],
        waf: { enabled: true, mode: 'On', load_owasp_crs: true, waf_mode: 'override' },
      });
    }
    const list = await api.post(`${API}/access-lists`, { headers: HEADERS, data: { name: 'Bypass deny all', defaultAction: 'deny', denyStatus: 451, denyBody: 'denied-by-list' } });
    expect(list.status(), await list.text()).toBe(201);
    aclId = ((await list.json()) as { id: number }).id;
    for (const provider of PROVIDERS) await createHost(provider, 'acl', 'full', ['203.0.113.0/24'], { accessListId: aclId });

    // Every host is live once it asks (or, behind the list that denies everyone, denies).
    for (const host of Object.values(hosts)) {
      await eventually(async () => {
        if (host.kind === 'acl') expect((await probe(host.domain, '/')).status).toBe(451);
        else host.provider.expectAsked(await probe(host.domain, host.kind === 'protected' ? '/admin/x' : '/'));
      });
    }
  });

  test.afterAll(async () => {
    const cleanup = await playwrightRequest.newContext({ storageState: resolve(__dirname, '../../.auth/admin.json') });
    // Never leave the client address read differently for the specs that follow.
    const restored = await cleanup.put(`${API}/settings/trusted-proxies`, { headers: HEADERS, data: originalTrustedProxies });
    expect(restored.ok(), await restored.text()).toBe(true);
    for (const id of created) await cleanup.delete(`${API}/proxy-hosts/${id}`, { headers: HEADERS });
    if (aclId !== null) await cleanup.delete(`${API}/access-lists/${aclId}`, { headers: HEADERS });
    await cleanup.dispose();
    await api?.dispose();
  });

  test('the client reaches Caddy from a private address', () => {
    expect(peer).toMatch(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/);
  });

  // ── the REST API ──────────────────────────────────────────────────────

  test.describe('the REST API', () => {
    const body = (provider: Provider, sources: unknown) => ({
      name: 'Bypass api check',
      domains: ['func-bsrc-api.test'],
      upstreams: [UPSTREAM],
      sslForced: false,
      [provider.field]: { ...provider.config([], 'full'), [provider.id === 'ingressi' ? 'bypass_sources' : 'bypassSources']: sources },
    });

    for (const provider of PROVIDERS) {
      const key = provider.id === 'ingressi' ? 'bypass_sources' : 'bypassSources';

      test(`${provider.label}: refuses entries that are not addresses, and stores nothing`, async () => {
        for (const [bad, message] of [
          [['10.0.0.5', 'office.example.com'], /office\.example\.com" is not an IP address/],
          [['10.0.0.0/33'], /is not an IP address/],
          [['0.0.0.0/0'], /matches every address/],
          [['::/0'], /matches every address/],
          [['{http.request.host}'], /is not an IP address/],
        ] as const) {
          const res = await api.post(`${API}/proxy-hosts`, { headers: HEADERS, data: body(provider, bad) });
          expect(res.status(), JSON.stringify(bad)).toBe(400);
          const error = String(((await res.json()) as { error: string }).error);
          expect(error).toContain(`${provider.field}.${key}`);
          expect(error).toMatch(message);
        }
        const list = (await (await api.get(`${API}/proxy-hosts`)).json()) as Array<{ domains: string[] }>;
        expect(list.some((host) => host.domains.includes('func-bsrc-api.test'))).toBe(false);
      });

      test(`${provider.label}: refuses more than 100 entries`, async () => {
        const many = Array.from({ length: 101 }, (_, index) => `10.${Math.floor(index / 250)}.${index % 250}.0/24`);
        const res = await api.post(`${API}/proxy-hosts`, { headers: HEADERS, data: body(provider, many) });
        expect(res.status()).toBe(400);
        expect(String(((await res.json()) as { error: string }).error)).toMatch(/at most 100 entries/);
      });

      test(`${provider.label}: an update that is refused leaves the list as it was`, async () => {
        const host = full(provider);
        const res = await api.put(`${API}/proxy-hosts/${host.id}`, { headers: HEADERS, data: { [provider.field]: provider.config(['203.0.113.0/24', 'nope'], 'full') } });
        expect(res.status()).toBe(400);
        const read = (await (await api.get(`${API}/proxy-hosts/${host.id}`)).json()) as Record<string, Record<string, unknown>>;
        expect(read[provider.field][key]).toEqual(['203.0.113.0/24']);
      });

      test(`${provider.label}: stores a list normalized and reads it back`, async () => {
        const host = full(provider);
        await setSources(host, ['203.0.113.77/24', '198.51.100.7', '203.0.113.0/24']);
        const read = (await (await api.get(`${API}/proxy-hosts/${host.id}`)).json()) as Record<string, Record<string, unknown>>;
        expect(read[provider.field][key]).toEqual(['203.0.113.0/24', '198.51.100.7']);
        await setSources(host, ['203.0.113.0/24']);
      });
    }
  });

  // ── who is asked, with the client at the address Caddy sees ───────────

  for (const provider of PROVIDERS) {
    test.describe(`${provider.label}: the list`, () => {
      test('asks a client that is not in the list, as it always did', async () => {
        const host = full(provider);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        provider.expectAsked(await probe(host.domain, '/deep/path?x=1'));
        provider.expectAsked(await probe(host.domain, '/admin/panel'));
      });

      test('lets a client in the list reach the app without being asked', async () => {
        const host = full(provider);
        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        expectThrough(await probe(host.domain, '/deep/path?x=1'));
        expectThrough(await probe(host.domain, '/admin/panel'));
        // A request that is not from a browser is let through just the same.
        expectThrough(await httpGet(host.domain, '/api/data', { Accept: 'application/json' }));
      });

      test('matches the exact address and the network around it, not only private_ranges', async () => {
        const host = full(provider);
        await setSources(host, [`${peer}/32`]);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        await setSources(host, [peerNetwork, '198.51.100.7']);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        // An address next to it is not the client.
        const [a, b, c, d] = peer.split('.').map(Number);
        await setSources(host, [`${a}.${b}.${c}.${(d + 1) % 256}`]);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
      });

      test('keeps asking a client whose network is not listed, whatever headers it sends', async () => {
        const host = full(provider);
        await setSources(host, ['192.168.77.0/24', '2001:db8::/32']);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        // Without a trusted proxy, headers say nothing about the client.
        const forged: Array<Record<string, string>> = [
          { 'X-Forwarded-For': '192.168.77.5' },
          { 'X-Real-IP': '192.168.77.5' },
          { Forwarded: 'for=192.168.77.5' },
          { 'X-Forwarded-For': '2001:db8::1' },
          { 'CF-Connecting-IP': '192.168.77.5', 'True-Client-IP': '192.168.77.5' },
        ];
        for (const headers of forged) provider.expectAsked(await probe(host.domain, '/', headers));
      });

      test('never passes identity headers a client forges to the app', async () => {
        const host = full(provider);
        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/who', provider.forged)));
        const res = await probe(host.domain, '/who', provider.forged);
        expect(res.body).not.toContain('mallory');
        for (const [name, value] of Object.entries(provider.forged)) expect(res.body).not.toContain(`${name}: ${value}`);
      });

      test('takes the list away again: asked as before, and a session still works', async () => {
        const host = full(provider);
        await setSources(host, []);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        if (provider.session) {
          const res = await probe(host.domain, '/', provider.session.headers);
          expectThrough(res, provider.session.identity);
        }
        const read = (await (await api.get(`${API}/proxy-hosts/${host.id}`)).json()) as Record<string, Record<string, unknown>>;
        expect(read[provider.field][provider.id === 'ingressi' ? 'bypass_sources' : 'bypassSources'] ?? []).toEqual([]);
      });

      test('a network of the other address family does not match', async () => {
        const host = full(provider);
        await setSources(host, ['2001:db8::/32', '::1']);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
      });

      test('a session works for a client the list does not cover, with the identity the check gives', async () => {
        test.skip(!provider.session, 'the built-in sign-in needs a portal login, covered by forward-auth.spec.ts');
        const host = full(provider);
        await setSources(host, ['203.0.113.0/24']);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        const res = await probe(host.domain, '/', provider.session!.headers);
        expectThrough(res, provider.session!.identity);
      });
    });
  }

  // ── paths ─────────────────────────────────────────────────────────────

  for (const provider of PROVIDERS) {
    test.describe(`${provider.label}: paths`, () => {
      test('all but some paths are asked: a listed client skips them all, the rest keep their exception', async () => {
        const host = hosts[`${provider.id}:excluded`];
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        expectThrough(await probe(host.domain, '/public/asset'));
        provider.expectAsked(await probe(host.domain, '/private/area'));

        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        expectThrough(await probe(host.domain, '/private/area'));
        expectThrough(await probe(host.domain, '/public/asset'));
      });

      test('only some paths are asked: a listed client skips them, and an unlisted one is asked as before', async () => {
        const host = hosts[`${provider.id}:protected`];
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/admin/panel')));
        expectThrough(await probe(host.domain, '/anything/else'));

        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/admin/panel')));
        expectThrough(await probe(host.domain, '/admin/deep/er'));
        expectThrough(await probe(host.domain, '/anything/else'));

        await setSources(host, ['203.0.113.0/24']);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/admin/panel')));
        expectThrough(await probe(host.domain, '/anything/else'));
      });
    });
  }

  // ── the rest of the host ──────────────────────────────────────────────

  for (const provider of PROVIDERS) {
    test.describe(`${provider.label}: only the sign-in is skipped`, () => {
      test('location rules: a listed client reaches their upstream, an unlisted one is asked', async () => {
        const host = hosts[`${provider.id}:rich`];
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/api/items')));
        provider.expectAsked(await probe(host.domain, '/'));

        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/api/items'), 'echo-server-2'));
        expectThrough(await probe(host.domain, '/'));
        expect((await probe(host.domain, '/api/items')).body).not.toContain(THROUGH);
      });

      test('path blocks still apply to a listed client', async () => {
        const host = hosts[`${provider.id}:rich`];
        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        for (const path of ['/blocked/secret', '/blocked/']) {
          const res = await probe(host.domain, path);
          expect(res.status, path).toBe(403);
          expect(res.body).toContain('blocked-by-host');
        }
      });

      test('the WAF still applies to a listed client', async () => {
        const host = hosts[`${provider.id}:rich`];
        await setSources(host, ['private_ranges']);
        await eventually(async () => expectThrough(await probe(host.domain, '/')));
        expectThrough(await probe(host.domain, '/search?q=hello+world&page=2'));
        const sql = await probe(host.domain, "/item?id=1'%20OR%20'1'%3D'1");
        expect(sql.status).toBe(403);
        expect(sql.body).not.toContain(THROUGH);
        const xss = await probe(host.domain, '/page?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
        expect(xss.status).toBe(403);
      });

      test('an unlisted client meets the same blocks before it is asked', async () => {
        const host = hosts[`${provider.id}:rich`];
        await setSources(host, ['203.0.113.0/24']);
        await eventually(async () => provider.expectAsked(await probe(host.domain, '/')));
        expect((await probe(host.domain, '/blocked/secret')).status).toBe(403);
        expect((await probe(host.domain, "/item?id=1'%20OR%20'1'%3D'1")).status).toBe(403);
      });

      test('the access list still decides: a listed client it denies gets the deny response', async () => {
        const host = hosts[`${provider.id}:acl`];
        await eventually(async () => expect((await probe(host.domain, '/')).status).toBe(451));
        await setSources(host, ['private_ranges']);
        await eventually(async () => expect((await probe(host.domain, '/api/items')).status).toBe(451));
        const res = await probe(host.domain, '/');
        expect(res.status).toBe(451);
        expect(res.body).toContain('denied-by-list');
        expect(res.body).not.toContain(THROUGH);
      });
    });
  }

  test.describe('Generic forward auth: next to the API-key bypass', () => {
    test('a listed client, a client with the key, and neither', async () => {
      // (Not /data: the whoami upstream answers that path itself, with an empty body.)
      const provider = PROVIDERS[1];
      const host = await createHost(provider, 'apikey', 'full', ['203.0.113.0/24'], {});
      const res = await api.put(`${API}/proxy-hosts/${host.id}`, {
        headers: HEADERS,
        data: { forwardAuth: { ...provider.config(['203.0.113.0/24'], 'full'), apiSplit: true, apiBypassHeaders: ['X-Api-Key'] } },
      });
      expect(res.status(), await res.text()).toBe(200);

      // The key alone (the request that tells the new settings from the first ones).
      await eventually(async () => expectThrough(await httpGet(host.domain, '/machine', { 'X-Api-Key': 'secret-key-123' })));
      // Neither listed nor carrying the key: asked (an API client gets 401).
      expect((await httpGet(host.domain, '/machine')).status).toBe(401);
      provider.expectAsked(await probe(host.domain, '/'));

      // The list alone, API client and browser alike.
      const listed = await api.put(`${API}/proxy-hosts/${host.id}`, {
        headers: HEADERS,
        data: { forwardAuth: { ...provider.config(['private_ranges'], 'full'), apiSplit: true, apiBypassHeaders: ['X-Api-Key'] } },
      });
      expect(listed.status(), await listed.text()).toBe(200);
      await eventually(async () => expectThrough(await httpGet(host.domain, '/machine')));
      expectThrough(await probe(host.domain, '/'));
      // Both: still through, with the forged identity removed.
      const both = await httpGet(host.domain, '/machine', { 'X-Api-Key': 'k', 'Remote-User': 'mallory' });
      expectThrough(both);
      expect(both.body).not.toContain('mallory');
    });
  });

  test.describe('Authentik: the outpost keeps answering', () => {
    test('listed or not, the outpost path reaches the outpost', async () => {
      const host = full(PROVIDERS[2]);
      for (const sources of [['private_ranges'], ['203.0.113.0/24']]) {
        await setSources(host, sources);
        await eventually(async () => {
          const res = await httpGet(host.domain, '/outpost.goauthentik.io/ping');
          expect(res.status).toBe(200);
          expect(res.body).toBe('outpost-ok');
        });
      }
    });
  });

  // ── the client address, with a trusted proxy ──────────────────────────

  test.describe('behind a trusted proxy', () => {
    const listed = ['192.168.77.0/24', '2001:db8::/32'];

    test.beforeAll(async () => {
      test.setTimeout(180_000);
      for (const provider of PROVIDERS) await setSources(full(provider), listed);
    });

    test.describe('X-Forwarded-For, read left to right', () => {
      test.beforeAll(async () => setTrustedProxies({ ranges: [`${peer}/32`] }));

      for (const provider of PROVIDERS) {
        test(`${provider.label}: the address in the header decides, and no header means the proxy itself`, async () => {
          const host = full(provider);
          await eventually(async () => expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5' })));
          expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.250' }));
          expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '2001:db8:1::5' }));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '203.0.113.7' }));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.78.5' }));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '2001:db9::1' }));
          provider.expectAsked(await probe(host.domain, '/'));
          // The proxy's own address is private, and not listed here.
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': peer }));
        });

        test(`${provider.label}: the first entry counts, so a client can forge it through a proxy that appends (why the editor warns)`, async () => {
          const host = full(provider);
          await eventually(async () => expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5, 203.0.113.7' })));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '203.0.113.7, 192.168.77.5' }));
        });

        test(`${provider.label}: a listed client still skips every path`, async () => {
          const host = full(provider);
          for (const path of ['/', '/admin/panel', '/a/b/c?d=e']) expectThrough(await probe(host.domain, path, { 'X-Forwarded-For': '192.168.77.9' }));
        });
      }
    });

    test.describe('X-Forwarded-For, strict', () => {
      test.beforeAll(async () => setTrustedProxies({ ranges: [`${peer}/32`], strict: true }));

      for (const provider of PROVIDERS) {
        test(`${provider.label}: the entry the proxy added counts, so that forgery fails`, async () => {
          const host = full(provider);
          await eventually(async () => provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5, 203.0.113.7' })));
          expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5' }));
          expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '2001:db8:1::5' }));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '203.0.113.7' }));
          provider.expectAsked(await probe(host.domain, '/'));
        });
      }
    });

    test.describe('a header of the administrator\'s choice', () => {
      test.beforeAll(async () => setTrustedProxies({ ranges: [`${peer}/32`], client_ip_headers: ['X-Real-Client'] }));

      for (const provider of PROVIDERS) {
        test(`${provider.label}: it replaces X-Forwarded-For`, async () => {
          const host = full(provider);
          await eventually(async () => expectThrough(await probe(host.domain, '/', { 'X-Real-Client': '192.168.77.5' })));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Real-Client': '203.0.113.7', 'X-Forwarded-For': '192.168.77.5' }));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5' }));
          provider.expectAsked(await probe(host.domain, '/'));
        });
      }
    });

    test.describe('a peer that is not trusted', () => {
      test.beforeAll(async () => setTrustedProxies({ ranges: ['198.51.100.0/24'] }));

      for (const provider of PROVIDERS) {
        test(`${provider.label}: its headers are ignored, in both directions`, async () => {
          const host = full(provider);
          await eventually(async () => provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5' })));
          provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '2001:db8::5' }));

          // Listed by the address the client really has, a forged header cannot take it away.
          await setSources(host, ['private_ranges']);
          await eventually(async () => expectThrough(await probe(host.domain, '/', { 'X-Forwarded-For': '203.0.113.7' })));
          expectThrough(await probe(host.domain, '/'));
          await setSources(host, listed);
        });
      }
    });

    test.describe('with the trusted proxies taken away', () => {
      test.beforeAll(async () => setTrustedProxies(originalTrustedProxies));

      for (const provider of PROVIDERS) {
        test(`${provider.label}: headers mean nothing again`, async () => {
          const host = full(provider);
          await eventually(async () => provider.expectAsked(await probe(host.domain, '/', { 'X-Forwarded-For': '192.168.77.5' })));
          provider.expectAsked(await probe(host.domain, '/'));
        });
      }
    });
  });
});
