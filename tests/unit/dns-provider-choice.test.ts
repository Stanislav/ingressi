/**
 * src/lib/dns-provider-choice.ts: the provider pickers' data and the challenge
 * a certificate ends up with, which mirrors the Caddy config builder: an
 * override naming a configured provider, else the default provider, else HTTP-01.
 */
import { describe, expect, it } from 'vitest';
import { buildDnsProviderChoices, describeChallenge, effectiveChallenge, NO_DNS_PROVIDERS } from '@/src/lib/dns-provider-choice';

const labelOf = (name: string) => ({ cloudflare: 'Cloudflare', godaddy: 'GoDaddy' })[name] ?? name;
const choices = buildDnsProviderChoices({ providers: { cloudflare: { api_token: 'secret' }, godaddy: { api_token: 'secret' } }, default: 'cloudflare' }, labelOf);

describe('buildDnsProviderChoices', () => {
  it('keeps names and labels only, never credentials', () => {
    expect(choices).toEqual({
      providers: [{ name: 'cloudflare', label: 'Cloudflare' }, { name: 'godaddy', label: 'GoDaddy' }],
      defaultProvider: 'cloudflare',
    });
    expect(JSON.stringify(choices)).not.toContain('secret');
  });

  it('has no default when none is set or the default is not configured', () => {
    expect(buildDnsProviderChoices({ providers: { godaddy: {} }, default: null }, labelOf).defaultProvider).toBeNull();
    expect(buildDnsProviderChoices({ providers: { godaddy: {} }, default: 'cloudflare' }, labelOf).defaultProvider).toBeNull();
  });

  it('is empty without DNS provider settings', () => {
    expect(buildDnsProviderChoices(null, labelOf)).toBe(NO_DNS_PROVIDERS);
  });
});

describe('effectiveChallenge', () => {
  it('uses the override when it names a configured provider', () => {
    expect(effectiveChallenge(choices, 'godaddy')).toEqual({ challenge: 'dns-01', provider: { name: 'godaddy', label: 'GoDaddy' }, fromDefault: false });
  });

  it('falls back to the default for no override or an unknown one', () => {
    expect(effectiveChallenge(choices, null)).toMatchObject({ challenge: 'dns-01', provider: { name: 'cloudflare' }, fromDefault: true });
    expect(effectiveChallenge(choices, 'route53')).toMatchObject({ challenge: 'dns-01', provider: { name: 'cloudflare' }, fromDefault: true });
  });

  it('is HTTP-01 without a default provider, unless the override names one', () => {
    const noDefault = buildDnsProviderChoices({ providers: { godaddy: {} }, default: null }, labelOf);
    expect(effectiveChallenge(noDefault, null)).toEqual({ challenge: 'http-01' });
    expect(effectiveChallenge(noDefault, 'godaddy')).toMatchObject({ challenge: 'dns-01', provider: { name: 'godaddy' } });
    expect(effectiveChallenge(NO_DNS_PROVIDERS, 'godaddy')).toEqual({ challenge: 'http-01' });
  });
});

describe('describeChallenge', () => {
  it('names the challenge and provider, marking the default', () => {
    expect(describeChallenge(effectiveChallenge(choices, 'godaddy'))).toBe('DNS-01 with GoDaddy');
    expect(describeChallenge(effectiveChallenge(choices, null))).toBe('DNS-01 with Cloudflare (default)');
    expect(describeChallenge({ challenge: 'http-01' })).toBe('HTTP-01');
  });
});
