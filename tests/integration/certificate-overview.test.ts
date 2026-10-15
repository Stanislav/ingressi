/**
 * The certificate overview (src/lib/certificate-overview.ts) against an
 * in-memory database: how each certificate is obtained, its expiry and
 * renewal, who uses it, and the visibility rules it shares with the
 * certificates page and GET /api/v1/certificates/overview (tag scope, L4
 * hosts only with l4_proxy_hosts:read).
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({
  db: null as unknown as TestDb,
  served: new Map<string, { validFrom: string; validTo: string; issuer: string | null; keyType: string | null }>(),
  /** Names Caddy answered without a certificate, and names whose handshake did not work. */
  none: new Set<string>(),
  unavailable: new Set<string>(),
  asked: [] as string[][],
  dnsProvider: null as null | { providers: Record<string, Record<string, string>>; default: string | null },
  acme: null as null | { caUrl?: string },
  access: null as unknown,
  guarded: [] as string[],
}));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});
vi.mock('../../src/lib/managed-certificates', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/managed-certificates')>()),
  getManagedCertificateReadings: vi.fn(async (domains: string[]) => {
    ctx.asked.push([...domains]);
    const checkedAt = '2026-10-03T11:59:00.000Z';
    const result = new Map();
    for (const domain of domains) {
      const cert = ctx.served.get(domain);
      if (cert) result.set(domain, { kind: 'served', expiry: { domain, checkedAt, ...cert } });
      else if (ctx.none.has(domain)) result.set(domain, { kind: 'none', checkedAt });
      else if (ctx.unavailable.has(domain)) result.set(domain, { kind: 'unavailable', checkedAt });
    }
    return result;
  }),
}));
vi.mock('../../src/lib/api-auth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/api-auth')>()),
  requireApiPermission: vi.fn(async (_request: unknown, permission: string) => {
    ctx.guarded.push(permission);
    return { userId: 1, access: ctx.access, authMethod: 'bearer' };
  }),
}));
vi.mock('../../src/lib/settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/settings')>()),
  getAcmeSettings: vi.fn(async () => ctx.acme),
  getDnsProviderSettings: vi.fn(async () => ctx.dnsProvider),
}));

import * as schema from '../../src/lib/db/schema';
import { adminAccess, type Access, type Permission } from '../../src/lib/permissions';
import { buildCertificateOverview, certificateRenewal, daysUntil } from '../../src/lib/certificate-overview';
import { createSelfSignedServerCertificate } from '../helpers/certs';
import { eq } from 'drizzle-orm';
import { GET as getOverview } from '../../app/api/v1/certificates/overview/route';
import { NextRequest } from 'next/server';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 3, 12);
const stamp = () => new Date(NOW).toISOString();
const iso = (offsetDays: number) => new Date(NOW + offsetDays * DAY).toISOString();

function role(permissions: Permission[], scopeTags: string[] = []): Access {
  return {
    userId: 7,
    role: 'viewer',
    isAdmin: false,
    customRole: { id: 1, name: 'Custom' },
    permissions: new Set(permissions),
    scopeTags,
  };
}

async function addHost(
  name: string,
  domains: string[],
  options: { enabled?: boolean; certificateId?: number | null; tags?: string[]; updatedAt?: string } = {}
) {
  const [row] = await ctx.db
    .insert(schema.proxyHosts)
    .values({
      name,
      domains: JSON.stringify(domains),
      upstreams: JSON.stringify(['10.0.0.1:80']),
      certificateId: options.certificateId ?? null,
      enabled: options.enabled ?? true,
      tags: JSON.stringify(options.tags ?? []),
      createdAt: stamp(),
      updatedAt: options.updatedAt ?? stamp(),
    })
    .returning();
  return row.id;
}

async function addImported(name: string, pem: string, domains: string[]) {
  const [row] = await ctx.db
    .insert(schema.certificates)
    .values({ name, type: 'imported', domainNames: JSON.stringify(domains), certificatePem: pem, privateKeyPem: 'x', autoRenew: false, createdAt: stamp(), updatedAt: stamp() })
    .returning();
  return row.id;
}

async function addL4(name: string, sni: string[], tlsTermination = true, tags: string[] = []) {
  await ctx.db.insert(schema.l4ProxyHosts).values({
    name,
    protocol: 'tcp',
    listenAddress: ':8883',
    upstreams: JSON.stringify(['mqtt:1883']),
    matcherType: sni.length ? 'tls_sni' : 'none',
    matcherValue: JSON.stringify(sni),
    tlsTermination,
    tags: JSON.stringify(tags),
    createdAt: stamp(),
    updatedAt: stamp(),
  });
}

let importedPem: string;

beforeAll(() => {
  // Valid from now for 20 days: in the 30-day window, so "replace soon".
  importedPem = createSelfSignedServerCertificate('files.example.com', ['files.example.com', '*.files.example.com'], 20).certificatePem;
});

beforeEach(async () => {
  for (const table of [schema.l4ProxyHosts, schema.proxyHosts, schema.certificates]) await ctx.db.delete(table);
  ctx.served.clear();
  ctx.none.clear();
  ctx.unavailable.clear();
  ctx.asked = [];
  ctx.dnsProvider = null;
  ctx.acme = null;
});

describe('certificateRenewal', () => {
  const acme = (validFrom: number, validTo: number, active = true) =>
    certificateRenewal({ kind: 'acme', active, validFrom: iso(validFrom), validTo: iso(validTo) }, NOW);

  it('schedules a 90-day certificate a third of its lifetime before expiry', () => {
    expect(acme(-10, 80)).toEqual({ state: 'scheduled', renewFrom: iso(50) });
  });

  it('is due inside the window, overdue past its middle, expired after', () => {
    expect(acme(-65, 25).state).toBe('due');
    expect(acme(-80, 10).state).toBe('overdue');
    expect(acme(-91, -1).state).toBe('expired');
  });

  it('follows short-lived certificates by their own lifetime', () => {
    // A 6-day certificate renews with 2 days left, not 30.
    expect(acme(-1, 5).state).toBe('scheduled');
    expect(acme(-4.5, 1.5).state).toBe('due');
  });

  it('marks imported certificates manual, then replace soon', () => {
    expect(certificateRenewal({ kind: 'imported', active: true, validFrom: iso(-10), validTo: iso(200) }, NOW).state).toBe('manual');
    expect(certificateRenewal({ kind: 'imported', active: true, validFrom: iso(-10), validTo: iso(20) }, NOW).state).toBe('replace_soon');
  });

  it('is unknown without an expiry and inactive for a disabled host', () => {
    expect(certificateRenewal({ kind: 'acme', active: true, validFrom: null, validTo: null }, NOW).state).toBe('unknown');
    expect(certificateRenewal({ kind: 'acme', active: false, validFrom: iso(-1), validTo: iso(80) }, NOW).state).toBe('inactive');
  });

  it('is pending for a new host without a certificate, missing once it has had a while, unknown when nothing was learned', () => {
    const none = (savedAt: string | null) =>
      certificateRenewal({ kind: 'acme', active: true, validFrom: null, validTo: null, noCertificate: { savedAt } }, NOW);
    expect(none(iso(-1 / 24 / 60))).toEqual({ state: 'pending', renewFrom: null });
    expect(none(iso(-14 / 24 / 60)).state).toBe('pending');
    expect(none(iso(-16 / 24 / 60)).state).toBe('missing');
    expect(none(iso(-30)).state).toBe('missing');
    expect(none(null).state).toBe('missing');
    expect(certificateRenewal({ kind: 'acme', active: false, validFrom: null, validTo: null, noCertificate: { savedAt: iso(-30) } }, NOW).state).toBe('inactive');
  });

  it('counts whole days left', () => {
    expect(daysUntil(iso(31.5), NOW)).toBe(31);
    expect(daysUntil(iso(-0.5), NOW)).toBe(-1);
  });
});

describe('buildCertificateOverview', () => {
  it('reads ACME expiry from what Caddy serves and names the hosts using it', async () => {
    const id = await addHost('Auth', ['auth.example.com', 'www.auth.example.com']);
    await addL4('MQTT', ['auth.example.com']);
    await addL4('Passthrough', ['auth.example.com'], false);
    ctx.served.set('auth.example.com', { validFrom: iso(-59), validTo: iso(31), issuer: "Let's Encrypt", keyType: 'ECDSA P-256' });
    ctx.served.set('www.auth.example.com', { validFrom: iso(-60), validTo: iso(30), issuer: "Let's Encrypt", keyType: 'ECDSA P-256' });

    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates).toHaveLength(1);
    const [row] = certificates;
    expect(row).toMatchObject({
      id: `acme:${id}`,
      kind: 'acme',
      issuer: "Let's Encrypt",
      issuerFromCertificate: true,
      keyType: 'ECDSA P-256',
      validTo: iso(30),
      daysLeft: 30,
      expirySource: 'caddy',
      obtainedBy: { method: 'acme', challenge: 'http-01', dnsProvider: null, directory: null },
    });
    expect(row.renewal.state).toBe('due');
    // L4 hosts that terminate TLS for the name use it; passthrough hosts do not.
    expect(row.usedBy.map((u) => `${u.kind}:${u.name}`)).toEqual(['proxy_host:Auth', 'l4_host:MQTT']);
    expect(ctx.asked.flat().sort()).toEqual(['auth.example.com', 'www.auth.example.com']);
  });

  it('tells a host still getting its first certificate from one that never got it', async () => {
    const fresh = await addHost('Fresh', ['fresh.example.com']);
    const stuck = await addHost('Stuck', ['stuck.example.com'], { updatedAt: iso(-1) });
    const unreadable = await addHost('Unreadable', ['unreadable.example.com'], { updatedAt: iso(-1) });
    const unasked = await addHost('Unasked', ['unasked.example.com'], { updatedAt: iso(-1) });
    ctx.none.add('fresh.example.com');
    ctx.none.add('stuck.example.com');
    ctx.unavailable.add('unreadable.example.com');

    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    const byHost = (id: number) => certificates.find((row) => row.id === `acme:${id}`)!;

    expect(byHost(fresh).renewal.state).toBe('pending');
    expect(byHost(stuck)).toMatchObject({ validTo: null, daysLeft: null, checkedAt: '2026-10-03T11:59:00.000Z', renewal: { state: 'missing' } });
    // Caddy could not be asked, or has not been yet: nothing is known about the certificate.
    expect(byHost(unreadable)).toMatchObject({ checkedAt: '2026-10-03T11:59:00.000Z', renewal: { state: 'unknown' } });
    expect(byHost(unasked)).toMatchObject({ checkedAt: null, renewal: { state: 'unknown' } });
  });

  it('counts a managed entry as missing from the last time it or a host using it was saved', async () => {
    const [entry] = await ctx.db
      .insert(schema.certificates)
      .values({ name: 'Shop', type: 'managed', domainNames: '["shop.example.com"]', autoRenew: true, createdAt: iso(-2), updatedAt: iso(-2) })
      .returning();
    const hostId = await addHost('Shop', ['shop.example.com'], { certificateId: entry.id, updatedAt: iso(-1 / 24 / 60) });
    ctx.none.add('shop.example.com');

    let row = (await buildCertificateOverview(adminAccess(1), { now: NOW })).certificates.find((r) => r.certificateId === entry.id)!;
    expect(row.renewal.state).toBe('pending');

    await ctx.db.update(schema.proxyHosts).set({ updatedAt: iso(-1) }).where(eq(schema.proxyHosts.id, hostId));
    row = (await buildCertificateOverview(adminAccess(1), { now: NOW })).certificates.find((r) => r.certificateId === entry.id)!;
    expect(row).toMatchObject({ kind: 'managed', renewal: { state: 'missing' } });
  });

  it('serves the certificate when another name of the host has one, whatever the rest answered', async () => {
    const id = await addHost('Two', ['one.example.com', 'two.example.com'], { updatedAt: iso(-1) });
    ctx.served.set('one.example.com', { validFrom: iso(-10), validTo: iso(80), issuer: "Let's Encrypt", keyType: 'ECDSA P-256' });
    ctx.none.add('two.example.com');
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates.find((row) => row.id === `acme:${id}`)!.renewal.state).toBe('scheduled');
  });

  it('says DNS-01 with the default provider and names a custom ACME directory', async () => {
    ctx.dnsProvider = { providers: { cloudflare: { api_token: 'secret' } }, default: 'cloudflare' };
    ctx.acme = { caUrl: 'https://user:pass@ca.example.com/acme/directory' };
    await addHost('Grafana', ['grafana.example.com']);
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates[0].obtainedBy).toEqual({ method: 'acme', challenge: 'dns-01', dnsProvider: 'Cloudflare', directory: 'ca.example.com' });
    // Without a served certificate the issuer is the configured CA, and nothing secret leaks.
    expect(certificates[0]).toMatchObject({ issuer: 'ca.example.com', issuerFromCertificate: false, validTo: null, daysLeft: null });
    expect(certificates[0].renewal.state).toBe('unknown');
    expect(JSON.stringify(certificates)).not.toMatch(/secret|pass@/);
  });

  it('lists imported certificates from their PEM and folds covered ACME hosts into them', async () => {
    const cert = await addImported('Files', importedPem, ['files.example.com']);
    await addHost('Files host', ['files.example.com'], { certificateId: cert });
    await addHost('Share', ['share.files.example.com']);
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: Date.now() });
    expect(certificates).toHaveLength(1);
    expect(certificates[0]).toMatchObject({
      kind: 'imported',
      certificateId: cert,
      domains: ['files.example.com', '*.files.example.com'],
      issuer: 'Ingressi E2E',
      keyType: 'RSA 2048',
      expirySource: 'pem',
      obtainedBy: { method: 'imported' },
    });
    expect(certificates[0].renewal.state).toBe('replace_soon');
    expect(certificates[0].usedBy.map((u) => u.name).sort()).toEqual(['Files host', 'Share']);
    expect(JSON.stringify(certificates)).not.toContain('BEGIN CERTIFICATE');
  });

  it('lists a wildcard ACME host once, with the hosts it covers', async () => {
    await addHost('Wildcard', ['*.apps.example.com']);
    await addHost('Sub', ['sub.apps.example.com']);
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates.map((row) => row.domains)).toEqual([['*.apps.example.com']]);
    expect(certificates[0].usedBy.map((u) => u.name)).toEqual(['Wildcard', 'Sub']);
  });

  it('does not ask Caddy about disabled hosts', async () => {
    await addHost('Off', ['off.example.com'], { enabled: false });
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates[0]).toMatchObject({ active: false, validTo: null });
    expect(certificates[0].renewal.state).toBe('inactive');
    expect(ctx.asked).toEqual([]);
  });

  it('sorts the soonest expiry first and unknown expiries last', async () => {
    await addHost('Later', ['later.example.com']);
    await addHost('Unknown', ['unknown.example.com']);
    await addHost('Soon', ['soon.example.com']);
    ctx.served.set('later.example.com', { validFrom: iso(-1), validTo: iso(89), issuer: null, keyType: null });
    ctx.served.set('soon.example.com', { validFrom: iso(-80), validTo: iso(10), issuer: null, keyType: null });
    const { certificates } = await buildCertificateOverview(adminAccess(1), { now: NOW });
    expect(certificates.map((row) => row.name)).toEqual(['Soon', 'Later', 'Unknown']);
  });

  it('keeps a tag-scoped role to its own hosts and certificates', async () => {
    const ours = await addImported('Ours', importedPem, ['files.example.com']);
    await addImported('Theirs', importedPem, ['files.example.com']);
    await addHost('A', ['a.example.com'], { tags: ['team-a'] });
    await addHost('B', ['b.example.com'], { tags: ['team-b'] });
    await addHost('A files', ['files.example.com'], { certificateId: ours, tags: ['team-a'] });
    await addL4('L4 A', ['a.example.com'], true, ['team-a']);
    const access = role(['certificates:read'], ['team-a']);
    const { certificates } = await buildCertificateOverview(access, { now: NOW });
    expect(certificates.map((row) => row.name).sort()).toEqual(['A', 'Ours']);
    // Without l4_proxy_hosts:read, L4 hosts are not named.
    expect(certificates.flatMap((row) => row.usedBy).some((u) => u.kind === 'l4_host')).toBe(false);
    expect(ctx.asked.flat()).toEqual(['a.example.com']);

    const withL4 = await buildCertificateOverview(role(['certificates:read', 'l4_proxy_hosts:read'], ['team-a']), { now: NOW });
    expect(withL4.certificates.find((row) => row.name === 'A')!.usedBy.map((u) => u.name)).toEqual(['A', 'L4 A']);
  });
});

describe('GET /api/v1/certificates/overview', () => {
  it('needs certificates:read and returns the caller\'s rows without key material', async () => {
    const cert = await addImported('Files', importedPem, ['files.example.com']);
    await addHost('Files host', ['files.example.com'], { certificateId: cert });
    ctx.access = adminAccess(1);
    ctx.guarded = [];
    const response = await getOverview(new NextRequest('http://localhost/api/v1/certificates/overview'));
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(ctx.guarded).toEqual(['certificates:read']);
    const body = await response.json();
    expect(body.certificates).toHaveLength(1);
    expect(body.certificates[0]).toMatchObject({ kind: 'imported', name: 'Files' });
    expect(JSON.stringify(body)).not.toMatch(/BEGIN|privateKey/);
  });
});
