/**
 * Addresses that skip sign-in: the generated Caddy config, for the built-in
 * sign-in, Authentik and generic forward auth alike.
 *
 * The routes that let those clients through must
 *  - be a twin of every route that asks for sign-in (same host and path),
 *    right before it, and be the only change: leave them out and the document
 *    is the one a host without the list gets. The server orders its routes by
 *    host and path, so a catch-all would lose to a protected path; the
 *    first-match tests below walk the final order the way Caddy does,
 *  - skip the sign-in and nothing else: they carry the host's other handlers
 *    (path blocks...) and strip the identity headers a client could forge,
 *  - match the client address the way access lists do (client_ip behind
 *    trusted proxies, remote_ip without),
 *  - cover the host's location rules and every domain group,
 *  - and never widen: only valid entries reach the config, and a provider that
 *    is off emits nothing.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

// Keep the real buildCaddyDocument (pure config builder) but stub the network
// apply so createProxyHost doesn't try to reach a live Caddy admin API.
vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

// The model and settings modules first (see caddy-test-mock-import-order).
import { createProxyHost, updateProxyHost } from '../../src/lib/models/proxy-hosts';
import { saveTrustedProxiesSettings } from '../../src/lib/settings';
import { buildCaddyDocument } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';
import { eq } from 'drizzle-orm';

const UPSTREAM = '10.0.0.5:8080';
const LOCATION_UPSTREAM = '10.0.0.9:9000';
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', 'fd00::/8', '::1/128'];
const COPY_HEADERS = ['Remote-User', 'Remote-Groups', 'Remote-Email', 'Remote-Name', 'Remote-IP'];

type Mode = 'full' | 'excluded' | 'protected';
type Provider = {
  name: string;
  key: 'authentik' | 'forwardAuth' | 'ingressiForwardAuth';
  /** The rewrite URI of the sign-in check. */
  authUri: string;
  /** A header the provider's identity strip removes. */
  stripped: string;
  config: (sources: string[], mode: Mode, enabled?: boolean) => Record<string, unknown>;
  /** Settings that split browser and API clients (generic forward auth only). */
  apiSplit?: Record<string, unknown>;
};

const PROVIDERS: Provider[] = [
  {
    name: 'Authentik',
    key: 'authentik',
    authUri: '/outpost.goauthentik.io/auth/caddy',
    stripped: 'X-Authentik-Username',
    config: (sources, mode, enabled = true) => ({
      enabled,
      outpostDomain: 'outpost.goauthentik.io',
      outpostUpstream: 'http://authentik-server:9000',
      copyHeaders: ['X-Authentik-Username', 'X-Authentik-Email'],
      ...(mode === 'excluded' ? { excludedPaths: ['/public/*'] } : {}),
      ...(mode === 'protected' ? { protectedPaths: ['/admin/*'] } : {}),
      bypassSources: sources,
    }),
  },
  {
    name: 'Generic forward auth',
    key: 'forwardAuth',
    authUri: '/api/authz/forward-auth',
    stripped: 'Remote-User',
    apiSplit: { apiSplit: true },
    config: (sources, mode, enabled = true) => ({
      enabled,
      provider: 'authelia',
      authUpstream: 'http://authelia:9091',
      authEndpoint: '/api/authz/forward-auth',
      copyHeaders: COPY_HEADERS,
      ...(mode === 'excluded' ? { excludedPaths: ['/public/*'] } : {}),
      ...(mode === 'protected' ? { protectedPaths: ['/admin/*'] } : {}),
      bypassSources: sources,
    }),
  },
  {
    name: 'Built-in sign-in',
    key: 'ingressiForwardAuth',
    authUri: '/api/forward-auth/verify',
    stripped: 'X-Ingressi-User',
    config: (sources, mode, enabled = true) => ({
      enabled,
      ...(mode === 'excluded' ? { excluded_paths: ['/public/*'] } : {}),
      ...(mode === 'protected' ? { protected_paths: ['/admin/*'] } : {}),
      bypass_sources: sources,
    }),
  },
];

// ── config-document helpers ─────────────────────────────────────────────

interface Route {
  match?: Array<Record<string, unknown>>;
  handle?: Array<Record<string, unknown>>;
  terminal?: boolean;
}

/** Every route object anywhere in the document, in document order. */
function collectRoutes(node: unknown, out: Route[] = []): Route[] {
  if (Array.isArray(node)) {
    for (const item of node) collectRoutes(item, out);
  } else if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.match) && Array.isArray(obj.handle)) out.push(obj as Route);
    for (const value of Object.values(obj)) collectRoutes(value, out);
  }
  return out;
}

const matcher = (route: Route): Record<string, unknown> => (route.match?.[0] ?? {}) as Record<string, unknown>;
const servesHost = (route: Route, host: string) => ((matcher(route).host as string[] | undefined) ?? []).includes(host);
const isAddressRoute = (route: Route) => 'remote_ip' in matcher(route) || 'client_ip' in matcher(route);
const hostRoutes = (doc: unknown, host: string) => collectRoutes(doc).filter((route) => servesHost(route, host));
/** The routes of the HTTP server, in the order Caddy tries them (not the routes inside handlers). */
const serverRoutes = (doc: unknown): Route[] =>
  (doc as { apps?: { http?: { servers?: { ingressi?: { routes?: Route[] } } } } }).apps?.http?.servers?.ingressi?.routes ?? [];

const isAuthCall = (handler: unknown, uri: string) => {
  const h = handler as Record<string, unknown>;
  return h?.handler === 'reverse_proxy' && (h.rewrite as { uri?: string } | undefined)?.uri === uri;
};
const dialsTo = (handler: unknown, dial: string) => {
  const h = handler as Record<string, unknown>;
  return h?.handler === 'reverse_proxy' && ((h.upstreams as Array<{ dial?: string }> | undefined) ?? []).some((upstream) => upstream.dial === dial);
};
const strips = (handler: unknown, header: string) => {
  const h = handler as Record<string, unknown>;
  const del = (h?.request as { delete?: string[] } | undefined)?.delete;
  return h?.handler === 'headers' && Array.isArray(del) && del.includes(header);
};

/** The document with every address-matched route taken out. */
function withoutAddressRoutes(node: unknown): unknown {
  if (Array.isArray(node)) {
    return node
      .filter((item) => !(item && typeof item === 'object' && Array.isArray((item as Route).match) && Array.isArray((item as Route).handle) && isAddressRoute(item as Route)))
      .map(withoutAddressRoutes);
  }
  if (node && typeof node === 'object') {
    return Object.fromEntries(Object.entries(node as Record<string, unknown>).map(([key, value]) => [key, withoutAddressRoutes(value)]));
  }
  return node;
}

async function makeHost(
  provider: Provider,
  sources: string[],
  options: { mode?: Mode; domains?: string[]; extra?: Record<string, unknown>; enabled?: boolean; split?: boolean } = {}
) {
  const host = await createProxyHost(
    {
      name: `host-${Math.random().toString(36).slice(2, 8)}`,
      domains: options.domains ?? ['app.example.com'],
      upstreams: [UPSTREAM],
      [provider.key]: { ...provider.config(sources, options.mode ?? 'full', options.enabled ?? true), ...(options.split ? provider.apiSplit : {}) },
      ...(options.extra ?? {}),
    } as never,
    1
  );
  return host as { id: number };
}

// ── walking the final route order the way Caddy does ────────────────────

type Request = { host: string; path: string; address: string; headers?: Record<string, string> };

function ipv4(address: string): number | null {
  const parts = address.split('.').map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts.reduce((total, part) => total * 256 + part, 0)
    : null;
}

function inRange(address: string, range: string): boolean {
  const [network, prefix = '32'] = range.split('/');
  const a = ipv4(address);
  const n = ipv4(network);
  if (a === null || n === null) return false;
  const shift = 32 - Number(prefix);
  return Math.floor(a / 2 ** shift) === Math.floor(n / 2 ** shift);
}

const escapeRegExp = (text: string) => text.replace(/[.+?^$|()[\]{}\\]/g, '\\$&');
const glob = (pattern: string) => new RegExp('^' + escapeRegExp(pattern).replace(/\*/g, '.*') + '$');

function matchesSet(set: Record<string, unknown>, request: Request): boolean {
  return Object.entries(set).every(([key, value]) => {
    switch (key) {
      case 'host':
        return (value as string[]).some(
          (host) => host === request.host || (host.startsWith('*.') && request.host.endsWith(host.slice(1)) && !request.host.slice(0, request.host.length - host.length + 1).includes('.'))
        );
      case 'path':
        return (value as string[]).some((pattern) => glob(pattern).test(request.path));
      case 'remote_ip':
      case 'client_ip':
        return (value as { ranges: string[] }).ranges.some((range) => inRange(request.address, range));
      case 'expression':
        // The redirect from http: these requests are https.
        return !String(value).includes('"http"');
      case 'header':
        return Object.entries(value as Record<string, string[]>).every(([name, patterns]) => {
          const sent = request.headers?.[name.toLowerCase()];
          return sent !== undefined && patterns.some((pattern) => glob(pattern).test(sent));
        });
      case 'not':
        return !(value as Array<Record<string, unknown>>).some((inner) => matchesSet(inner, request));
      default:
        throw new Error(`The test does not know the matcher ${key}`);
    }
  });
}

/** The first route that takes the request, as Caddy picks it. */
function firstMatch(routes: Route[], request: Request): Route | undefined {
  return routes.find((route) => (route.match ?? []).some((set) => matchesSet(set, request)));
}

const asksForSignIn = (route: Route | undefined, provider: Provider) => Boolean(route?.handle?.some((handler) => isAuthCall(handler, provider.authUri)));
const upstreamOf = (route: Route | undefined) =>
  [LOCATION_UPSTREAM, UPSTREAM].find((dial) => route?.handle?.some((handler) => dialsTo(handler, dial)));

/** Whether the sign-in covers `path`, for the paths the tests use. */
function covered(mode: Mode, path: string): boolean {
  if (mode === 'excluded') return !path.startsWith('/public/');
  if (mode === 'protected') return path.startsWith('/admin/');
  return true;
}

const INSIDE = '192.168.1.9';
const OUTSIDE = '203.0.113.9';
const PATHS = ['/', '/admin/panel', '/public/page', '/api/items', '/other/deep/path'];

beforeEach(async () => {
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.users).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: 'admin@example.com',
    name: 'Admin',
    role: 'admin',
    provider: 'credentials',
    subject: 'admin',
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  await saveTrustedProxiesSettings({ ranges: [] });
});

describe.each(PROVIDERS)('$name: addresses that skip sign-in', (provider) => {
  it('emits nothing without a list', async () => {
    await makeHost(provider, []);
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    expect(routes.some(isAddressRoute)).toBe(false);
    expect(routes.some((route) => route.handle!.some((handler) => isAuthCall(handler, provider.authUri)))).toBe(true);
  });

  it('puts a twin for the listed addresses right before every route that asks for sign-in', async () => {
    await makeHost(provider, ['192.168.1.0/24', '203.0.113.9']);
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');

    const bypass = routes.filter(isAddressRoute);
    expect(bypass).toHaveLength(1);
    expect(matcher(bypass[0])).toEqual({ host: ['app.example.com'], remote_ip: { ranges: ['192.168.1.0/24', '203.0.113.9'] } });
    expect(bypass[0].terminal).toBe(true);

    const asking = routes.filter((route) => route.handle!.some((handler) => isAuthCall(handler, provider.authUri)));
    expect(asking.length).toBeGreaterThan(0);
    for (const route of asking) {
      const twin = routes[routes.indexOf(route) - 1];
      expect(isAddressRoute(twin)).toBe(true);
      expect(matcher(twin).host).toEqual(matcher(route).host);
      expect(matcher(twin).path).toEqual(matcher(route).path);
    }
  });

  it('lets those clients through to the upstream with no sign-in check', async () => {
    await makeHost(provider, ['192.168.1.0/24']);
    const [bypass] = hostRoutes(await buildCaddyDocument(), 'app.example.com').filter(isAddressRoute);
    expect(bypass.handle!.some((handler) => isAuthCall(handler, provider.authUri))).toBe(false);
    expect(bypass.handle!.at(-1) && dialsTo(bypass.handle!.at(-1), UPSTREAM)).toBe(true);
  });

  it('strips the identity headers a client could forge, before the upstream', async () => {
    await makeHost(provider, ['192.168.1.0/24']);
    const [bypass] = hostRoutes(await buildCaddyDocument(), 'app.example.com').filter(isAddressRoute);
    const stripIndex = bypass.handle!.findIndex((handler) => strips(handler, provider.stripped));
    const upstreamIndex = bypass.handle!.findIndex((handler) => dialsTo(handler, UPSTREAM));
    expect(stripIndex).toBeGreaterThanOrEqual(0);
    expect(stripIndex).toBeLessThan(upstreamIndex);
  });

  it('keeps the host\'s other handlers on those routes: only the sign-in is skipped', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { extra: { pathBlocks: [{ path: '/private/*', status: 403 }] } });
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    const [bypass] = routes.filter(isAddressRoute);
    const signedIn = routes.find((route) => route.handle!.some((handler) => isAuthCall(handler, provider.authUri)))!;
    const blocks = (route: Route) =>
      route.handle!.some(
        (handler) =>
          handler.handler === 'subroute' &&
          JSON.stringify(handler).includes('"status_code":403') &&
          JSON.stringify(handler).includes('/private/*')
      );
    expect(blocks(signedIn)).toBe(true);
    expect(blocks(bypass)).toBe(true);
    // The handler chain is the signed-in route's, without the check itself.
    const chain = (route: Route) => route.handle!.filter((handler) => !isAuthCall(handler, provider.authUri) && !dialsTo(handler, UPSTREAM));
    expect(JSON.stringify(chain(bypass))).toBe(JSON.stringify(chain(signedIn)));
  });

  it('expands private_ranges into networks and writes ranges as their network address', async () => {
    await makeHost(provider, ['private_ranges', '203.0.113.77/24', '203.0.113.5']);
    const [bypass] = hostRoutes(await buildCaddyDocument(), 'app.example.com').filter(isAddressRoute);
    expect(matcher(bypass).remote_ip).toEqual({ ranges: [...PRIVATE_RANGES, '203.0.113.0/24', '203.0.113.5'] });
    expect(JSON.stringify(bypass)).not.toContain('private_ranges');
  });

  it('matches the client address behind trusted proxies, the connection\'s address without', async () => {
    await makeHost(provider, ['192.168.1.0/24']);
    expect(matcher(hostRoutes(await buildCaddyDocument(), 'app.example.com').find(isAddressRoute)!)).toHaveProperty('remote_ip');

    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'] });
    const behind = matcher(hostRoutes(await buildCaddyDocument(), 'app.example.com').find(isAddressRoute)!);
    expect(behind).toHaveProperty('client_ip');
    expect(behind).not.toHaveProperty('remote_ip');
    expect(behind.client_ip).toEqual({ ranges: ['192.168.1.0/24'] });
  });

  it('is the only difference to the host without the list', async () => {
    const host = await makeHost(provider, []);
    const without = JSON.stringify(withoutAddressRoutes(await buildCaddyDocument()));
    await updateProxyHost(host.id, { [provider.key]: provider.config(['192.168.1.0/24'], 'full') } as never, 1);
    const withList = await buildCaddyDocument();
    expect(JSON.stringify(withList)).not.toBe(without);
    expect(JSON.stringify(withoutAddressRoutes(withList))).toBe(without);
  });

  it.each<Mode>(['excluded', 'protected'])('is still the only difference when the sign-in is limited by paths (%s)', async (mode) => {
    const host = await makeHost(provider, [], { mode });
    const without = JSON.stringify(withoutAddressRoutes(await buildCaddyDocument()));
    await updateProxyHost(host.id, { [provider.key]: provider.config(['192.168.1.0/24'], mode) } as never, 1);
    const doc = await buildCaddyDocument();
    const bypass = hostRoutes(doc, 'app.example.com').filter(isAddressRoute);
    // Excluded paths: the catch-all asks for sign-in. Protected paths: /admin/* does, the rest does not.
    expect(bypass.map((route) => matcher(route).path)).toEqual(mode === 'protected' ? [['/admin/*']] : [undefined]);
    expect(JSON.stringify(withoutAddressRoutes(doc))).toBe(without);
  });

  it('gives no twin to routes that ask for no sign-in', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { mode: 'excluded' });
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    const excluded = routes.find((route) => (matcher(route).path as string[] | undefined)?.[0] === '/public/*')!;
    expect(isAddressRoute(excluded)).toBe(false);
    expect(excluded.handle!.some((handler) => isAuthCall(handler, provider.authUri))).toBe(false);
    expect(routes.filter(isAddressRoute).some((route) => (matcher(route).path as string[] | undefined)?.[0] === '/public/*')).toBe(false);
  });

  it('gives the host\'s location rules their own routes for those clients, in front of the catch-all', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { extra: { locationRules: [{ path: '/api/*', upstreams: [LOCATION_UPSTREAM] }] } });
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com').filter(isAddressRoute);
    expect(routes).toHaveLength(2);
    const [location, catchAll] = routes;
    expect(matcher(location)).toEqual({ host: ['app.example.com'], remote_ip: { ranges: ['192.168.1.0/24'] }, path: ['/api/*'] });
    expect(location.handle!.some((handler) => dialsTo(handler, LOCATION_UPSTREAM))).toBe(true);
    expect(location.handle!.some((handler) => dialsTo(handler, UPSTREAM))).toBe(false);
    expect(location.handle!.some((handler) => isAuthCall(handler, provider.authUri))).toBe(false);
    expect(matcher(catchAll)).not.toHaveProperty('path');
    expect(catchAll.handle!.some((handler) => dialsTo(handler, UPSTREAM))).toBe(true);
  });

  it('covers every group of the host\'s domains', async () => {
    const host = await makeHost(provider, ['192.168.1.0/24'], { domains: ['app.example.com'] });
    // A wildcard needs a DNS provider to be created; the document builder does not.
    await ctx.db.update(schema.proxyHosts).set({ domains: JSON.stringify(['app.example.com', '*.example.com']) }).where(eq(schema.proxyHosts.id, host.id));
    const bypass = collectRoutes(await buildCaddyDocument()).filter(isAddressRoute);
    expect(bypass.map((route) => matcher(route).host)).toEqual([['app.example.com'], ['*.example.com']]);
  });

  it('is left out while the provider is off', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { enabled: false });
    const doc = await buildCaddyDocument();
    expect(collectRoutes(doc).some(isAddressRoute)).toBe(false);
    expect(JSON.stringify(doc)).not.toContain('192.168.1.0/24');
  });

  it('keeps only valid entries, whatever storage holds', async () => {
    const host = await makeHost(provider, ['192.168.1.0/24']);
    const [row] = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, host.id));
    const meta = JSON.parse(row.meta as string) as Record<string, Record<string, unknown>>;
    const section = provider.key === 'ingressiForwardAuth' ? 'cpm_forward_auth' : provider.key === 'forwardAuth' ? 'forward_auth' : 'authentik';
    meta[section].bypass_sources = ['192.168.1.0/24', '0.0.0.0/0', '::/0', 'nonsense', 'office.example.com', '{http.request.host}', 42, null, '1.1.1.1/33', '203.0.113.9'];
    await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, host.id));

    const doc = await buildCaddyDocument();
    const [bypass] = hostRoutes(doc, 'app.example.com').filter(isAddressRoute);
    expect(matcher(bypass).remote_ip).toEqual({ ranges: ['192.168.1.0/24', '203.0.113.9'] });
    const json = JSON.stringify(doc);
    for (const bad of ['0.0.0.0/0', '::/0', 'nonsense', 'office.example.com', '1.1.1.1/33']) expect(json).not.toContain(bad);
  });

  it('emits no address route when nothing stored is valid', async () => {
    const host = await makeHost(provider, ['192.168.1.0/24']);
    const [row] = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, host.id));
    const meta = JSON.parse(row.meta as string) as Record<string, Record<string, unknown>>;
    const section = provider.key === 'ingressiForwardAuth' ? 'cpm_forward_auth' : provider.key === 'forwardAuth' ? 'forward_auth' : 'authentik';
    meta[section].bypass_sources = ['0.0.0.0/0', '::/0', 'nonsense'];
    await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, host.id));
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    expect(routes.some(isAddressRoute)).toBe(false);
    expect(routes.some((route) => route.handle!.some((handler) => isAuthCall(handler, provider.authUri)))).toBe(true);
  });

  it('applies to the host it is set on only', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { domains: ['skips.example.com'] });
    await makeHost(provider, [], { domains: ['asks.example.com'] });
    const doc = await buildCaddyDocument();
    expect(hostRoutes(doc, 'skips.example.com').some(isAddressRoute)).toBe(true);
    expect(hostRoutes(doc, 'asks.example.com').some(isAddressRoute)).toBe(false);
  });
});

describe('Authentik: the outpost keeps answering everyone', () => {
  it('leaves the outpost route as it was, for listed clients too', async () => {
    await makeHost(PROVIDERS[0], ['192.168.1.0/24']);
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    const outpost = routes.find((route) => (matcher(route).path as string[] | undefined)?.[0] === '/outpost.goauthentik.io/*');
    expect(outpost).toBeDefined();
    expect(isAddressRoute(outpost!)).toBe(false);
    for (const address of [INSIDE, OUTSIDE]) {
      expect(firstMatch(routes, { host: 'app.example.com', path: '/outpost.goauthentik.io/start', address })).toBe(outpost);
    }
  });
});

describe('built-in sign-in: the portal callback keeps answering everyone else', () => {
  it('leaves the callback route in place for clients that are not listed', async () => {
    await makeHost(PROVIDERS[2], ['192.168.1.0/24']);
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    const callback = routes.find((route) => JSON.stringify(route.handle).includes('/api/forward-auth/callback'));
    expect(callback).toBeDefined();
    expect(isAddressRoute(callback!)).toBe(false);
  });
});

describe('generic forward auth: next to the API-key bypass', () => {
  it('keeps both, ahead of the routes that check', async () => {
    const provider = PROVIDERS[1];
    await makeHost(provider, ['192.168.1.0/24'], { mode: 'full' });
    const [row] = await ctx.db.select().from(schema.proxyHosts);
    const meta = JSON.parse(row.meta as string) as Record<string, Record<string, unknown>>;
    meta.forward_auth.api_bypass_headers = ['X-Api-Key'];
    meta.forward_auth.api_split = true;
    await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, row.id));

    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    const addressIndex = routes.findIndex(isAddressRoute);
    const apiKeyIndex = routes.findIndex((route) => JSON.stringify(matcher(route).header ?? {}).includes('X-Api-Key'));
    const firstCheck = routes.findIndex((route) => route.handle!.some((handler) => isAuthCall(handler, '/api/authz/forward-auth')));
    expect(addressIndex).toBeGreaterThanOrEqual(0);
    expect(apiKeyIndex).toBeGreaterThanOrEqual(0);
    // Both skip the check, so both come before the routes that make it.
    expect(addressIndex).toBeLessThan(firstCheck);
    expect(apiKeyIndex).toBeLessThan(firstCheck);
    // Browser and API catch-alls still ask for sign-in.
    expect(routes.filter((route) => route.handle!.some((handler) => isAuthCall(handler, '/api/authz/forward-auth'))).length).toBe(2);
  });
});

describe.each(PROVIDERS)('$name: who is asked to sign in, request by request', (provider) => {
  const modes: Mode[] = ['full', 'excluded', 'protected'];
  const variants = provider.apiSplit ? [false, true] : [false];

  describe.each(modes.flatMap((mode) => variants.map((split) => [mode, split] as const)))('%s paths, API split %s', (mode, split) => {
    const requests = PATHS.flatMap((path): Array<{ path: string; headers: Record<string, string> }> => [
      { path, headers: {} },
      ...(split ? [{ path, headers: { accept: 'text/html' } }] : []),
    ]);

    it('listed clients are never asked, and everyone else is asked exactly as before', async () => {
      const host = await makeHost(provider, [], {
        mode,
        split,
        extra: { locationRules: [{ path: '/api/*', upstreams: [LOCATION_UPSTREAM] }] },
      });
      const before = hostRoutes(await buildCaddyDocument(), 'app.example.com');
      const expectedForOutsiders = requests.map(({ path, headers }) => JSON.stringify(firstMatch(before, { host: 'app.example.com', path, address: OUTSIDE, headers })));
      // Without the list, the sign-in covers what the mode says, for everyone.
      for (const { path, headers } of requests) {
        for (const address of [INSIDE, OUTSIDE]) {
          expect(asksForSignIn(firstMatch(before, { host: 'app.example.com', path, address, headers }), provider), `${path} before`).toBe(covered(mode, path));
        }
      }

      await updateProxyHost(host.id, { [provider.key]: { ...provider.config(['192.168.1.0/24'], mode), ...(split ? provider.apiSplit : {}) } } as never, 1);
      const after = hostRoutes(await buildCaddyDocument(), 'app.example.com');

      for (const { path, headers } of requests) {
        const label = `${path} ${JSON.stringify(headers)}`;
        const inside = firstMatch(after, { host: 'app.example.com', path, address: INSIDE, headers });
        const outside = firstMatch(after, { host: 'app.example.com', path, address: OUTSIDE, headers });
        // The listed client reaches the same upstream, with no sign-in anywhere.
        expect(asksForSignIn(inside, provider), `${label} inside`).toBe(false);
        expect(upstreamOf(inside), `${label} inside upstream`).toBe(path.startsWith('/api/') ? LOCATION_UPSTREAM : UPSTREAM);
        // Everyone else is asked where they were asked.
        expect(asksForSignIn(outside, provider), `${label} outside`).toBe(covered(mode, path));
      }
      // And the routes that take them are the very ones that took them before.
      expect(requests.map(({ path, headers }) => JSON.stringify(firstMatch(after, { host: 'app.example.com', path, address: OUTSIDE, headers })))).toEqual(expectedForOutsiders);
    });
  });

  it('a request from an address outside the list and a forged X-Forwarded-For is asked (no trusted proxies)', async () => {
    await makeHost(provider, ['192.168.1.0/24']);
    const routes = hostRoutes(await buildCaddyDocument(), 'app.example.com');
    // The matcher reads the connection's address, not a header the client sends.
    const forged = firstMatch(routes, { host: 'app.example.com', path: '/', address: OUTSIDE, headers: { 'x-forwarded-for': INSIDE } });
    expect(asksForSignIn(forged, provider)).toBe(true);
    expect(JSON.stringify(routes.filter(isAddressRoute))).not.toContain('x-forwarded-for');
  });

  it('covers another host\'s paths the same way: only the listed host skips', async () => {
    await makeHost(provider, ['192.168.1.0/24'], { domains: ['skips.example.com'] });
    await makeHost(provider, [], { domains: ['asks.example.com'] });
    const doc = await buildCaddyDocument();
    const all = serverRoutes(doc);
    expect(asksForSignIn(firstMatch(all, { host: 'skips.example.com', path: '/', address: INSIDE }), provider)).toBe(false);
    expect(asksForSignIn(firstMatch(all, { host: 'skips.example.com', path: '/', address: OUTSIDE }), provider)).toBe(true);
    expect(asksForSignIn(firstMatch(all, { host: 'asks.example.com', path: '/', address: INSIDE }), provider)).toBe(true);
  });
});
