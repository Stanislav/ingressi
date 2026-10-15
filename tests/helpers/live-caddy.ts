/**
 * What the running Caddy serves, read from inside its container through the
 * admin API: the TLS automation policies the dashboard generated.
 */
import { execFileSync } from 'node:child_process';

const CADDY = 'ingressi-caddy';

export type Policy = {
  subjects?: string[];
  issuers?: { challenges?: { dns?: { provider?: { name?: string } } } }[];
};

/** Caddy's live TLS automation policies; null if unreachable. */
export function fetchLivePolicies(): Policy[] | null {
  try {
    const out = execFileSync(
      'docker',
      ['exec', CADDY, 'wget', '-qO-', 'http://localhost:2019/config/apps/tls/automation/policies'],
      { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return JSON.parse(out) as Policy[] | null;
  } catch {
    return null;
  }
}

/** The DNS provider name Caddy uses for `domain`, or null when no policy lists it. */
export function liveProviderFor(domain: string): string | null {
  const policy = fetchLivePolicies()?.find((p) => p.subjects?.includes(domain));
  if (!policy) return null;
  return policy.issuers?.[0]?.challenges?.dns?.provider?.name ?? null;
}
