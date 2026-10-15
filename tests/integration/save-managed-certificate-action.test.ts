/**
 * saveManagedCertificateAction (app/(dashboard)/certificates/actions.ts): the
 * certificate sheet's way to create or change a certificate Caddy obtains,
 * with its own DNS provider or the default one. Expected failures come back
 * as `{ ok: false, error }`, since a thrown message does not reach the browser
 * in production.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import { certificates, users } from '../../src/lib/db/schema';
import { first } from '@/src/lib/db/ops';

let db: TestDb;

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => db));
vi.mock('../../src/lib/caddy', () => ({ applyCaddyConfig: vi.fn() }));
vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));

const dns = vi.hoisted(() => ({
  settings: null as null | { providers: Record<string, Record<string, string>>; default: string | null },
}));
vi.mock('../../src/lib/settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/settings')>()),
  getDnsProviderSettings: vi.fn(async () => dns.settings),
}));

const guard = vi.hoisted(() => ({ access: null as unknown, userId: 1 }));
vi.mock('@/src/lib/auth', () => ({
  requirePermission: vi.fn(async () => ({ user: { id: String(guard.userId) }, access: guard.access })),
}));

const { saveManagedCertificateAction } = await import('../../app/(dashboard)/certificates/actions');
const { applyCaddyConfig } = await import('../../src/lib/caddy');
const { adminAccess } = await import('../../src/lib/permissions');
const { updateCertificate } = await import('../../src/lib/models/certificates');

const stamp = () => new Date().toISOString();

beforeEach(async () => {
  db = createTestDb();
  vi.clearAllMocks();
  dns.settings = {
    providers: { cloudflare: { api_token: 'x' }, godaddy: { api_token: 'y' } },
    default: 'cloudflare',
  };
  const [admin] = await db.insert(users).values({
    email: 'admin@example.com', name: 'Admin', role: 'admin',
    provider: 'credentials', subject: 'admin@example.com', status: 'active',
    createdAt: stamp(), updatedAt: stamp(),
  }).returning();
  guard.userId = admin.id;
  guard.access = adminAccess(admin.id);
});

const rowOf = async (id: number) => first(db.select().from(certificates).where(eq(certificates.id, id)).limit(1));

describe('saveManagedCertificateAction', () => {
  it('creates a managed certificate with its own DNS provider and applies the config', async () => {
    const result = await saveManagedCertificateAction({ name: ' Shop ', domainNames: ['Shop.Example.com', 'shop.example.com.'], provider: 'godaddy' });

    expect(result).toMatchObject({ ok: true, certificate: { name: 'Shop', domains: ['shop.example.com'], provider: 'godaddy' } });
    const id = (result as { ok: true; certificate: { id: number } }).certificate.id;
    const row = await rowOf(id);
    expect(row).toMatchObject({ name: 'Shop', type: 'managed', autoRenew: true });
    expect(JSON.parse(row!.providerOptions!)).toEqual({ provider: 'godaddy' });
    expect(applyCaddyConfig).toHaveBeenCalled();
  });

  it('stores no override for the default provider choice', async () => {
    const result = await saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: null });
    expect(result).toMatchObject({ ok: true, certificate: { provider: null } });
    expect((await rowOf((result as { ok: true; certificate: { id: number } }).certificate.id))!.providerOptions).toBeNull();
  });

  it('changes the provider, then clears it back to the default', async () => {
    const created = await saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: 'godaddy' });
    const id = (created as { ok: true; certificate: { id: number } }).certificate.id;

    const renamed = await saveManagedCertificateAction({ id, name: 'Shop 2', domainNames: ['shop.example.com', 'www.shop.example.com'], provider: 'cloudflare' });
    expect(renamed).toMatchObject({ ok: true, certificate: { name: 'Shop 2', domains: ['shop.example.com', 'www.shop.example.com'], provider: 'cloudflare' } });
    expect(JSON.parse((await rowOf(id))!.providerOptions!)).toEqual({ provider: 'cloudflare' });

    const cleared = await saveManagedCertificateAction({ id, name: 'Shop 2', domainNames: ['shop.example.com'], provider: null });
    expect(cleared).toMatchObject({ ok: true, certificate: { provider: null } });
    expect((await rowOf(id))!.providerOptions).toBeNull();
  });

  it('refuses a provider that is not set up, without storing anything', async () => {
    const result = await saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: 'route53' });
    expect(result).toEqual({ ok: false, error: expect.stringContaining('not set up') });
    expect(await db.select().from(certificates)).toHaveLength(0);

    dns.settings = null;
    expect(await saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: 'cloudflare' })).toMatchObject({ ok: false });
  });

  it('refuses an empty name and invalid or missing domains', async () => {
    expect(await saveManagedCertificateAction({ name: '  ', domainNames: ['a.example.com'], provider: null })).toEqual({ ok: false, error: expect.stringContaining('name') });
    expect(await saveManagedCertificateAction({ name: 'X', domainNames: [], provider: null })).toMatchObject({ ok: false });
    expect(await saveManagedCertificateAction({ name: 'X', domainNames: ['bad_domain!'], provider: null })).toEqual({ ok: false, error: expect.stringContaining('bad_domain!') });
    expect(await db.select().from(certificates)).toHaveLength(0);
  });

  it('does not change an imported certificate or a missing one', async () => {
    const imported = await first(db.insert(certificates).values({
      name: 'Imported', type: 'imported', domainNames: '["a.example.com"]', autoRenew: false,
      certificatePem: 'pem', privateKeyPem: 'key', createdAt: stamp(), updatedAt: stamp(),
    }).returning());
    expect(await saveManagedCertificateAction({ id: imported!.id, name: 'X', domainNames: ['a.example.com'], provider: null })).toMatchObject({ ok: false });
    expect(await saveManagedCertificateAction({ id: 9999, name: 'X', domainNames: ['a.example.com'], provider: null })).toMatchObject({ ok: false });
    expect((await rowOf(imported!.id))!.name).toBe('Imported');
  });

  it('is refused for a role limited by a tag scope when creating', async () => {
    guard.access = {
      userId: 7, role: 'viewer', isAdmin: false, customRole: { id: 1, name: 'Scoped' },
      permissions: new Set(['certificates:write', 'certificates:read']), scopeTags: ['team-a'],
    };
    await expect(saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: null })).rejects.toThrow(/tag scope/);
    expect(await db.select().from(certificates)).toHaveLength(0);
  });
});

describe('updateCertificate providerOptions', () => {
  it('keeps the override when the field is left out and clears it with null', async () => {
    const created = await saveManagedCertificateAction({ name: 'Shop', domainNames: ['shop.example.com'], provider: 'godaddy' });
    const id = (created as { ok: true; certificate: { id: number } }).certificate.id;

    await updateCertificate(id, { name: 'Renamed' }, guard.userId);
    expect(JSON.parse((await rowOf(id))!.providerOptions!)).toEqual({ provider: 'godaddy' });

    await updateCertificate(id, { providerOptions: null }, guard.userId);
    expect((await rowOf(id))!.providerOptions).toBeNull();
  });
});
