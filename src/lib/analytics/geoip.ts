/**
 * Country and network (autonomous system) of a client address, from the
 * GeoLite2 databases in /usr/share/GeoIP. Both are
 * optional: without a database the lookup answers null / 0, and analytics
 * simply lack that dimension.
 */
import { existsSync } from 'node:fs';
import maxmind, { type AsnResponse, type CountryResponse } from 'maxmind';

export const GEOIP_COUNTRY_DB = '/usr/share/GeoIP/GeoLite2-Country.mmdb';
export const GEOIP_ASN_DB = '/usr/share/GeoIP/GeoLite2-ASN.mmdb';

/** The part of a maxmind Reader the lookups use (tests pass their own). */
export type GeoReader<T> = { get(ip: string): T | null };

export type IpInfo = {
  /** ISO 3166-1 alpha-2 country code, or null when unknown. */
  country: string | null;
  /** Autonomous system number, 0 when unknown. */
  asn: number;
  /** Autonomous system organisation, empty when unknown. */
  asOrg: string;
};

const CACHE_LIMIT = 10_000;
const AS_ORG_MAX_LENGTH = 128;

let countryReader: GeoReader<CountryResponse> | null = null;
let asnReader: GeoReader<AsnResponse> | null = null;
const cache = new Map<string, IpInfo>();

async function openReader<T extends CountryResponse | AsnResponse>(path: string, label: string): Promise<GeoReader<T> | null> {
  if (!existsSync(path)) {
    console.log(`[geoip] ${label} database not found at ${path}`);
    return null;
  }
  try {
    // The file is replaced now and then; reload it when it does.
    return await maxmind.open<T>(path, { watchForUpdates: true, watchForUpdatesNonPersistent: true });
  } catch (err) {
    console.warn(`[geoip] failed to load the ${label} database: ${(err as Error).message}`);
    return null;
  }
}

/** Opens both databases (once; later calls are no-ops unless `force`). */
let initialised = false;
export async function initGeoIp(force = false): Promise<void> {
  if (initialised && !force) return;
  initialised = true;
  countryReader = await openReader<CountryResponse>(GEOIP_COUNTRY_DB, 'GeoLite2-Country');
  asnReader = await openReader<AsnResponse>(GEOIP_ASN_DB, 'GeoLite2-ASN');
  cache.clear();
}

/** Replaces the readers (tests); null removes one. */
export function setGeoReaders(readers: { country?: GeoReader<CountryResponse> | null; asn?: GeoReader<AsnResponse> | null }): void {
  if ('country' in readers) countryReader = readers.country ?? null;
  if ('asn' in readers) asnReader = readers.asn ?? null;
  initialised = true;
  cache.clear();
}

/** Strips control characters and caps the length of a database string. */
function cleanOrg(value: unknown): string {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, AS_ORG_MAX_LENGTH);
}

/** Country and autonomous system of `ip`, cached. Never throws. */
export function lookupIp(ip: string): IpInfo {
  const empty: IpInfo = { country: null, asn: 0, asOrg: '' };
  if (!ip) return empty;
  const cached = cache.get(ip);
  if (cached) return cached;
  if (cache.size >= CACHE_LIMIT) cache.clear();

  let country: string | null;
  let asn = 0;
  let asOrg = '';
  try {
    const code = countryReader?.get(ip)?.country?.iso_code;
    country = typeof code === 'string' && /^[A-Z]{2}$/.test(code) ? code : null;
  } catch {
    country = null;
  }
  try {
    const record = asnReader?.get(ip);
    const number = record?.autonomous_system_number;
    if (typeof number === 'number' && Number.isInteger(number) && number > 0 && number <= 0xffffffff) {
      asn = number;
      asOrg = cleanOrg(record?.autonomous_system_organization);
    }
  } catch {
    asn = 0;
    asOrg = '';
  }
  const info = { country, asn, asOrg };
  cache.set(ip, info);
  return info;
}
