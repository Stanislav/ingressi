/**
 * Addresses that skip sign-in over the REST API, with a real database:
 * the field of each sign-in provider (authentik.bypassSources,
 * forwardAuth.bypassSources, ingressiForwardAuth.bypass_sources) is validated
 * strictly (400, nothing stored), stored normalized, kept by unrelated
 * updates, cleared on request, read back as stored, and documented.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

vi.mock('../../src/lib/caddy', () => ({
  applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

vi.mock('../../src/lib/api-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/api-auth')>();
  const { builtInAccess } = await import('../../src/lib/permissions');
  return {
    ...actual,
    requireApiPermission: vi.fn(async () => ({ userId: 1, role: 'admin', authMethod: 'bearer', access: builtInAccess(1, 'admin') })),
  };
});

import { POST as createHost } from '../../app/api/v1/proxy-hosts/route';
import { GET as getHost, PUT as updateHost } from '../../app/api/v1/proxy-hosts/[id]/route';
import { GET as getOpenApi } from '../../app/api/v1/openapi.json/route';
import * as schema from '../../src/lib/db/schema';
import { applyCaddyConfig } from '../../src/lib/caddy';
import { eq } from 'drizzle-orm';

function request(method: string, body?: unknown): any {
  return {
    headers: { get: () => null },
    method,
    nextUrl: { pathname: '/api/v1/proxy-hosts', searchParams: new URLSearchParams() },
    json: async () => body,
  };
}

const hostId = (id: number) => ({ params: Promise.resolve({ id: String(id) }) });

type Provider = {
  name: string;
  /** The host field, the field of the sources in it, and the meta key it is stored under. */
  host: 'authentik' | 'forwardAuth' | 'ingressiForwardAuth';
  field: 'bypassSources' | 'bypass_sources';
  metaKey: 'authentik' | 'forward_auth' | 'cpm_forward_auth';
  config: (extra: Record<string, unknown>) => Record<string, unknown>;
};

const PROVIDERS: Provider[] = [
  {
    name: 'Authentik',
    host: 'authentik',
    field: 'bypassSources',
    metaKey: 'authentik',
    config: (extra) => ({ enabled: true, outpostDomain: 'outpost.goauthentik.io', outpostUpstream: 'http://authentik-server:9000', ...extra }),
  },
  {
    name: 'Generic forward auth',
    host: 'forwardAuth',
    field: 'bypassSources',
    metaKey: 'forward_auth',
    config: (extra) => ({ enabled: true, provider: 'authelia', authUpstream: 'http://authelia:9091', ...extra }),
  },
  {
    name: 'Built-in sign-in',
    host: 'ingressiForwardAuth',
    field: 'bypass_sources',
    metaKey: 'cpm_forward_auth',
    config: (extra) => ({ enabled: true, ...extra }),
  },
];

const base = (extra: Record<string, unknown> = {}) => ({ name: 'App', domains: ['app.example.com'], upstreams: ['10.0.0.5:8080'], ...extra });

async function storedMeta(id: number): Promise<Record<string, Record<string, unknown>>> {
  const [row] = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, id));
  return JSON.parse((row.meta as string | null) ?? '{}');
}

beforeEach(async () => {
  vi.mocked(applyCaddyConfig).mockClear();
  for (const table of [schema.proxyHosts, schema.users]) await ctx.db.delete(table).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials', subject: 'admin',
    status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  });
});

describe.each(PROVIDERS)('$name: bypass sources over the API', (provider) => {
  const create = async (sources: unknown) => createHost(request('POST', base({ [provider.host]: provider.config({ [provider.field]: sources }) })));
  const sourcesOf = (host: Record<string, any>) => host[provider.host][provider.field] as string[] | null | undefined;

  it('stores them normalized and reads them back', async () => {
    const response = await create(['192.168.1.77/24', '203.0.113.5', 'private_ranges', '192.168.1.0/24', '2001:DB8::/32']);
    expect(response.status).toBe(201);
    const created = await response.json();
    expect(sourcesOf(created)).toEqual(['192.168.1.0/24', '203.0.113.5', 'private_ranges', '2001:db8::/32']);

    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toEqual(['192.168.1.0/24', '203.0.113.5', 'private_ranges', '2001:db8::/32']);

    const read = await getHost(request('GET'), hostId(created.id));
    expect(sourcesOf(await read.json())).toEqual(['192.168.1.0/24', '203.0.113.5', 'private_ranges', '2001:db8::/32']);
    expect(applyCaddyConfig).toHaveBeenCalled();
  });

  it('reads as none for a host without any', async () => {
    const response = await create(undefined);
    expect(response.status).toBe(201);
    const created = await response.json();
    expect(sourcesOf(created) ?? []).toEqual([]);
    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toBeUndefined();
  });

  it.each([
    ['an entry that is not an address', ['10.0.0.5', 'office.example.com'], /office\.example\.com" is not an IP address, a CIDR range or private_ranges/],
    ['a prefix that is too long', ['10.0.0.0/33'], /is not an IP address/],
    ['a range that matches every address', ['0.0.0.0/0'], /matches every address/],
    ['an IPv6 range that matches every address', ['::/0'], /matches every address/],
    ['a placeholder', ['{http.request.header.X-Real-Ip}'], /is not an IP address/],
    ['an entry that is not text', [10], /must be a string/],
    ['something that is not a list', { 0: '10.0.0.5' }, /must be an array/],
  ])('refuses %s with a 400 that names the field, and stores nothing', async (_label, sources, message) => {
    const response = await create(sources);
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toMatch(new RegExp(`${provider.host}\\.${provider.field}`));
    expect(body.error).toMatch(message);
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(0);
    expect(applyCaddyConfig).not.toHaveBeenCalled();
  });

  it('refuses more than 100 entries', async () => {
    const many = Array.from({ length: 101 }, (_, index) => `10.${Math.floor(index / 250)}.${index % 250}.0/24`);
    const response = await create(many);
    expect(response.status).toBe(400);
    expect((await response.json()).error).toMatch(/at most 100 entries/);
    const ok = await create(many.slice(0, 100));
    expect(ok.status).toBe(201);
  });

  it('keeps them through an update of something else, and changes them when asked', async () => {
    const created = await (await create(['192.168.1.0/24'])).json();

    const renamed = await updateHost(request('PUT', { name: 'Renamed' }), hostId(created.id));
    expect(renamed.status).toBe(200);
    expect(sourcesOf(await renamed.json())).toEqual(['192.168.1.0/24']);

    const upstreams = await updateHost(request('PUT', { upstreams: ['10.0.0.6:8080'] }), hostId(created.id));
    expect(sourcesOf(await upstreams.json())).toEqual(['192.168.1.0/24']);

    const changed = await updateHost(request('PUT', { [provider.host]: provider.config({ [provider.field]: ['10.1.0.0/16'] }) }), hostId(created.id));
    expect(changed.status).toBe(200);
    expect(sourcesOf(await changed.json())).toEqual(['10.1.0.0/16']);
    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toEqual(['10.1.0.0/16']);
  });

  it('keeps them when an update names the provider without the field', async () => {
    const created = await (await create(['192.168.1.0/24'])).json();
    const response = await updateHost(request('PUT', { [provider.host]: provider.config({}) }), hostId(created.id));
    expect(response.status).toBe(200);
    expect(sourcesOf(await response.json())).toEqual(['192.168.1.0/24']);
    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toEqual(['192.168.1.0/24']);
  });

  it.each([[[]], [null]])('removes them when sent as %j', async (empty) => {
    const created = await (await create(['192.168.1.0/24'])).json();
    const response = await updateHost(request('PUT', { [provider.host]: provider.config({ [provider.field]: empty }) }), hostId(created.id));
    expect(response.status).toBe(200);
    expect(sourcesOf(await response.json()) ?? []).toEqual([]);
    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toBeUndefined();
  });

  it('leaves the stored list as it was when an update is refused', async () => {
    const created = await (await create(['192.168.1.0/24'])).json();
    vi.mocked(applyCaddyConfig).mockClear();
    const refused = await updateHost(request('PUT', { [provider.host]: provider.config({ [provider.field]: ['192.168.1.0/24', 'nope'] }) }), hostId(created.id));
    expect(refused.status).toBe(400);
    expect((await storedMeta(created.id))[provider.metaKey].bypass_sources).toEqual(['192.168.1.0/24']);
    expect(applyCaddyConfig).not.toHaveBeenCalled();
  });

  it('is documented in the OpenAPI schema', async () => {
    const spec = await (await getOpenApi(request('GET'))).json();
    const schemaName = provider.host === 'authentik' ? 'AuthentikConfig' : provider.host === 'forwardAuth' ? 'ForwardAuthConfig' : 'IngressiForwardAuthConfig';
    const property = spec.components.schemas[schemaName]?.properties?.[provider.field];
    expect(property, `${schemaName}.${provider.field}`).toBeDefined();
    expect(property.items).toEqual({ type: 'string' });
    expect(property.description).toMatch(/skip sign-in/);
  });
});

describe('the sign-in providers keep their own lists', () => {
  it('a list on one provider is not seen by another', async () => {
    const created = await (
      await createHost(request('POST', base({ authentik: PROVIDERS[0].config({ bypassSources: ['192.168.1.0/24'] }), forwardAuth: PROVIDERS[1].config({ enabled: false }) })))
    ).json();
    expect(created.forwardAuth.bypassSources ?? []).toEqual([]);
    expect(created.authentik.bypassSources).toEqual(['192.168.1.0/24']);
  });

  it('switching to another provider does not carry a list over', async () => {
    const created = await (await createHost(request('POST', base({ authentik: PROVIDERS[0].config({ bypassSources: ['192.168.1.0/24'] }) })))).json();
    const switched = await updateHost(
      request('PUT', { authentik: { enabled: false }, ingressiForwardAuth: { enabled: true } }),
      hostId(created.id)
    );
    expect(switched.status).toBe(200);
    const host = await switched.json();
    expect(host.ingressiForwardAuth.bypass_sources ?? []).toEqual([]);
  });
});
