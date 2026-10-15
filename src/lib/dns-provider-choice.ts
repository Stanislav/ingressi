/**
 * The DNS providers a certificate can be obtained with, for the pickers in the
 * certificate sheet and the host editor. Names and labels only: credentials
 * never leave the server. Pure, so client components can import it.
 */

export type DnsProviderOption = { name: string; label: string };

export type DnsProviderChoices = {
  /** Every provider with credentials under Certificate settings, in the order stored. */
  providers: DnsProviderOption[];
  /** The default provider's name, or null when none is set (certificates then use HTTP-01). */
  defaultProvider: string | null;
};

export const NO_DNS_PROVIDERS: DnsProviderChoices = { providers: [], defaultProvider: null };

type StoredDnsProviders = { providers: Record<string, unknown>; default: string | null } | null;

/** The choices for the stored DNS provider settings; `labelOf` gives a provider's display name. */
export function buildDnsProviderChoices(settings: StoredDnsProviders, labelOf: (name: string) => string): DnsProviderChoices {
  if (!settings) return NO_DNS_PROVIDERS;
  const providers = Object.keys(settings.providers).map((name) => ({ name, label: labelOf(name) }));
  const defaultProvider = settings.default && settings.providers[settings.default] ? settings.default : null;
  return { providers, defaultProvider };
}

/** How a managed certificate is obtained: DNS-01 with a provider, or Caddy's default HTTP-01. */
export type EffectiveChallenge =
  | { challenge: "dns-01"; provider: DnsProviderOption; fromDefault: boolean }
  | { challenge: "http-01" };

/**
 * What the Caddy config builder does for a certificate with this provider
 * override (src/lib/caddy.ts): an override names a configured provider, else
 * the default provider, else no DNS challenge. Automatic hosts pass null.
 */
export function effectiveChallenge(choices: DnsProviderChoices, override: string | null): EffectiveChallenge {
  const own = override ? choices.providers.find((provider) => provider.name === override) : undefined;
  if (own) return { challenge: "dns-01", provider: own, fromDefault: false };
  const fallback = choices.defaultProvider ? choices.providers.find((provider) => provider.name === choices.defaultProvider) : undefined;
  if (fallback) return { challenge: "dns-01", provider: fallback, fromDefault: true };
  return { challenge: "http-01" };
}

/** "DNS-01 with GoDaddy", "DNS-01 with Cloudflare (default)" or "HTTP-01". */
export function describeChallenge(effective: EffectiveChallenge): string {
  if (effective.challenge === "http-01") return "HTTP-01";
  return `DNS-01 with ${effective.provider.label}${effective.fromDefault ? " (default)" : ""}`;
}
