/**
 * Addresses that skip sign-in through the dashboard's form actions
 * (app/(dashboard)/proxy-hosts/actions.ts), which older forms and the
 * approval flow still use: the field of each sign-in provider is read from the
 * form, normalized, refused when it is not an address, and left alone by a
 * form that does not carry it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestDb, type TestDb } from '../helpers/db';
import { ADMIN, hostRow, seedApprovals } from '../helpers/approvals';

const ctx = vi.hoisted(() => {
  const { mkdirSync } = require('node:fs');
  const { join } = require('node:path');
  const { tmpdir } = require('node:os');
  const dir = join(tmpdir(), `bypass-form-test-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  process.env.L4_PORTS_DIR = dir;
  return { db: null as unknown as TestDb, sessionUserId: 0 };
});

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));
vi.mock('@/src/lib/auth', async (importOriginal) => importOriginal());
vi.mock('@/src/lib/auth-server', () => ({
  getAuth: () => ({
    api: { getSession: async () => ({ user: { id: ctx.sessionUserId }, session: { id: 1, createdAt: new Date() } }) },
  }),
  reloadOAuthProviders: async () => {},
}));
vi.mock('next/headers', () => ({ headers: async () => new Headers() }));
vi.mock('next/navigation', () => ({ redirect: (url: string) => { throw new Error(`REDIRECT:${url}`); } }));
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));

import { applyCaddyConfig } from '../../src/lib/caddy';
import { createProxyHostAction, updateProxyHostAction } from '../../app/(dashboard)/proxy-hosts/actions';

beforeEach(async () => {
  ctx.db = createTestDb();
  vi.clearAllMocks();
  vi.mocked(applyCaddyConfig).mockResolvedValue(undefined as never);
  await seedApprovals(ctx.db);
  ctx.sessionUserId = ADMIN;
});

function form(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(values)) data.set(key, value);
  return data;
}

async function storedMeta(id: number): Promise<Record<string, Record<string, unknown>>> {
  return JSON.parse(((await hostRow(ctx.db, id))!.meta as string | null) ?? '{}');
}

const PROVIDERS: Array<{ name: string; metaKey: string; fields: Record<string, string>; sources: string }> = [
  {
    name: 'Authentik',
    metaKey: 'authentik',
    fields: {
      authentikPresent: '1',
      authentikEnabledPresent: '1',
      authentikEnabled: 'on',
      authentikOutpostDomain: 'outpost.example.com',
      authentikOutpostUpstream: 'http://outpost:9000',
    },
    sources: 'authentikBypassSources',
  },
  {
    name: 'Generic forward auth',
    metaKey: 'forward_auth',
    fields: {
      forwardAuthPresent: '1',
      forwardAuthEnabledPresent: '1',
      forwardAuthEnabled: 'on',
      forwardAuthProvider: 'authelia',
      forwardAuthUpstream: 'http://authelia:9091',
    },
    sources: 'forwardAuthBypassSources',
  },
  {
    name: 'Built-in sign-in',
    metaKey: 'cpm_forward_auth',
    fields: {
      ingressiForwardAuthPresent: '1',
      ingressiForwardAuthEnabledPresent: '1',
      ingressiForwardAuthEnabled: 'on',
    },
    sources: 'ingressiForwardAuthBypassSources',
  },
];

describe.each(PROVIDERS)('$name: form actions', ({ metaKey, fields, sources }) => {
  it('read the addresses separated by commas, spaces or new lines, and store them normalized', async () => {
    const created = await createProxyHostAction(
      undefined,
      form({ name: 'Form host', domains: 'form.example.com', upstreams: 'backend:8080', ...fields, [sources]: '192.168.1.77/24, 10.0.0.5\nprivate_ranges  192.168.1.0/24' })
    );
    expect(created).toMatchObject({ status: 'success' });
    const id = (await ctx.db.query.proxyHosts.findFirst({ where: (t, { eq }) => eq(t.name, 'Form host') }))!.id;
    expect((await storedMeta(id))[metaKey].bypass_sources).toEqual(['192.168.1.0/24', '10.0.0.5', 'private_ranges']);
  });

  it('refuse an entry that is not an address, and store nothing', async () => {
    const refused = await createProxyHostAction(
      undefined,
      form({ name: 'Bad host', domains: 'bad.example.com', upstreams: 'backend:8080', ...fields, [sources]: '10.0.0.5, office.example.com' })
    );
    expect(refused).toMatchObject({ status: 'error', message: expect.stringContaining('office.example.com') });
    expect(await ctx.db.query.proxyHosts.findFirst({ where: (t, { eq }) => eq(t.name, 'Bad host') })).toBeUndefined();
    const everyone = await createProxyHostAction(
      undefined,
      form({ name: 'Open host', domains: 'open.example.com', upstreams: 'backend:8080', ...fields, [sources]: '0.0.0.0/0' })
    );
    expect(everyone).toMatchObject({ status: 'error', message: expect.stringContaining('matches every address') });
  });

  it('change the list of a host, clear it with an empty field, and keep it when the form has no such field', async () => {
    await createProxyHostAction(undefined, form({ name: 'Keeper', domains: 'keep.example.com', upstreams: 'backend:8080', ...fields, [sources]: '192.168.1.0/24' }));
    const id = (await ctx.db.query.proxyHosts.findFirst({ where: (t, { eq }) => eq(t.name, 'Keeper') }))!.id;

    expect(await updateProxyHostAction(id, undefined, form({ name: 'Renamed', ...fields }))).toMatchObject({ status: 'success' });
    expect((await storedMeta(id))[metaKey].bypass_sources).toEqual(['192.168.1.0/24']);

    expect(await updateProxyHostAction(id, undefined, form({ ...fields, [sources]: '10.1.0.0/16' }))).toMatchObject({ status: 'success' });
    expect((await storedMeta(id))[metaKey].bypass_sources).toEqual(['10.1.0.0/16']);

    expect(await updateProxyHostAction(id, undefined, form({ ...fields, [sources]: '' }))).toMatchObject({ status: 'success' });
    expect((await storedMeta(id))[metaKey].bypass_sources).toBeUndefined();
  });
});
