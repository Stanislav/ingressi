/**
 * The host's protection summary counts the addresses that skip sign-in of the
 * provider that is on (and only that one), so the list and the overview can
 * say that the sign-in has exceptions.
 */
import { describe, expect, it, vi } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

import type { ProxyHost } from '../../src/lib/models/proxy-hosts';
import { protectionInputFor } from '../../src/lib/proxy-host-insights';
import { protectionsOf } from '../../src/lib/proxy-host-view';

const globals = { waf: null, geo: null, rateLimit: null };

const host = {
  id: 1,
  name: 'App',
  domains: ['app.example.com'],
  upstreams: ['http://10.0.0.5:8080'],
  accessListId: null,
  waf: null,
  mtls: null,
  geoblock: null,
  geoblockMode: 'merge',
  rateLimit: null,
  authentik: null,
  forwardAuth: null,
  ingressiForwardAuth: null,
} as unknown as ProxyHost;

const authentik = (bypassSources: string[], enabled = true) =>
  ({ enabled, outpostDomain: 'o', outpostUpstream: 'http://o', authEndpoint: null, copyHeaders: [], trustedProxies: [], setOutpostHostHeader: true, protectedPaths: null, excludedPaths: null, bypassSources }) as ProxyHost['authentik'];
const generic = (bypassSources: string[], enabled = true) =>
  ({ enabled, provider: 'authelia', authUpstream: 'http://a', authEndpoint: null, copyHeaders: [], trustedProxies: [], apiSplit: false, apiBypassHeaders: [], protectedPaths: null, excludedPaths: null, bypassSources }) as ProxyHost['forwardAuth'];
const builtIn = (bypass_sources: string[] | undefined, enabled = true) =>
  ({ enabled, protected_paths: null, excluded_paths: null, bypass_sources }) as ProxyHost['ingressiForwardAuth'];

describe('protectionInputFor', () => {
  it('counts the addresses of the sign-in that is on', () => {
    expect(protectionInputFor({ ...host, authentik: authentik(['10.0.0.0/8', '192.168.1.0/24']) }, globals).signInSkippedFor).toBe(2);
    expect(protectionInputFor({ ...host, forwardAuth: generic(['private_ranges']) }, globals).signInSkippedFor).toBe(1);
    expect(protectionInputFor({ ...host, ingressiForwardAuth: builtIn(['10.0.0.0/8', '203.0.113.9', '2001:db8::/32']) }, globals).signInSkippedFor).toBe(3);
  });

  it('counts none for a sign-in that is off, a list that is empty or a host without sign-in', () => {
    expect(protectionInputFor({ ...host, authentik: authentik(['10.0.0.0/8'], false) }, globals).signInSkippedFor).toBe(0);
    expect(protectionInputFor({ ...host, ingressiForwardAuth: builtIn(undefined) }, globals).signInSkippedFor).toBe(0);
    expect(protectionInputFor({ ...host, forwardAuth: generic([]) }, globals).signInSkippedFor).toBe(0);
    expect(protectionInputFor(host, globals).signInSkippedFor).toBe(0);
  });

  it('reaches the pill\'s title', () => {
    const pills = protectionsOf(protectionInputFor({ ...host, authentik: authentik(['10.0.0.0/8']) }, globals));
    expect(pills.find((pill) => pill.key === 'sign_in')?.title).toBe('Visitors sign in through Authentik; 1 address skips it');
  });
});
