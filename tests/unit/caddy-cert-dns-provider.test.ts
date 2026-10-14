import { describe, it, expect, vi, beforeEach } from 'vitest';

// Use the real caddy module (it is globally mocked in setup.vitest.ts).
vi.unmock('@/src/lib/caddy');

vi.mock('@/src/lib/settings', async (orig) => {
  const actual = await orig<typeof import('@/src/lib/settings')>();
  return { ...actual, getDnsProviderSettings: vi.fn() };
});

import { buildTlsAutomation } from '@/src/lib/caddy';
import { getDnsProviderSettings } from '@/src/lib/settings';

const NO_DNS = { enabled: false, resolvers: [] };

// providerOptions is stored in the database as a JSON string.
function managedCert(providerOptions: string | null) {
  return new Map<number, any>([
    [
      1,
      {
        certificate: {
          id: 1,
          type: 'managed',
          autoRenew: true,
          domainNames: 'managed.example.com',
          providerOptions,
        },
        domains: new Set(['managed.example.com']),
      },
    ],
  ]);
}

async function managedIssuer(providerOptions: string | null) {
  const result = await buildTlsAutomation(managedCert(providerOptions), new Set(), {
    dnsSettings: NO_DNS,
    acmeSettings: {},
  });
  const policies = (result.tlsApp as any).automation.policies as any[];
  return policies[0].issuers[0];
}

describe('buildTlsAutomation — per-certificate DNS provider', () => {
  beforeEach(() => {
    vi.mocked(getDnsProviderSettings).mockResolvedValue({
      default: 'cloudflare',
      providers: {
        cloudflare: { api_token: 'cf-token' },
        godaddy: { api_token: 'key:secret' },
      },
    });
  });

  it('uses the certificate provider instead of the global default', async () => {
    const issuer = await managedIssuer(JSON.stringify({ provider: 'godaddy' }));
    expect(issuer.challenges.dns.provider).toMatchObject({
      name: 'godaddy',
      api_token: 'key:secret',
    });
  });

  it('falls back to the global default when the certificate has no override', async () => {
    const issuer = await managedIssuer(null);
    expect(issuer.challenges.dns.provider).toMatchObject({
      name: 'cloudflare',
      api_token: 'cf-token',
    });
  });

  it('falls back to the global default when the override names an unconfigured provider', async () => {
    const issuer = await managedIssuer(JSON.stringify({ provider: 'route53' }));
    expect(issuer.challenges.dns.provider.name).toBe('cloudflare');
  });

  it('falls back to the global default when the stored override is malformed', async () => {
    const issuer = await managedIssuer('{not-json');
    expect(issuer.challenges.dns.provider.name).toBe('cloudflare');
  });
});
