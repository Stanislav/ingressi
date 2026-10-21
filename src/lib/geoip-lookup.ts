/**
 * Approximate place of a client address, from the GeoLite2 Country and ASN
 * databases in the geoip-data volume (the geo blocker uses them too).
 * Lookups happen in this process when a page or the API asks;
 * nothing they return is stored. Either database may be missing: the lookup
 * then answers with what the other one knows, or null.
 */
import { existsSync, statSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";
import maxmind, { type AsnResponse, type CountryResponse, type Reader } from "maxmind";

export const COUNTRY_DATABASE_PATH = "/usr/share/GeoIP/GeoLite2-Country.mmdb";
export const ASN_DATABASE_PATH = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";

export type IpLocation = {
  /** ISO 3166-1 alpha-2, e.g. "IT"; null when unknown. */
  countryCode: string | null;
  /** English country name, e.g. "Italy"; null when unknown. */
  country: string | null;
  /** Autonomous system number; null when unknown. */
  asn: number | null;
  /** The network's operator, e.g. "Telecom Italia"; null when unknown. */
  network: string | null;
};

type Opened<T extends AsnResponse | CountryResponse> = { reader: Reader<T>; mtimeMs: number } | null;

const state = globalThis as typeof globalThis & {
  __ingressiGeoipLookup?: {
    country: Opened<CountryResponse> | undefined;
    asn: Opened<AsnResponse> | undefined;
    checkedAt: number;
  };
};

/** How often a changed database file is picked up. */
const RECHECK_MS = 10 * 60 * 1000;

async function open<T extends AsnResponse | CountryResponse>(path: string): Promise<Opened<T>> {
  try {
    if (!existsSync(path)) return null;
    const mtimeMs = statSync(path).mtimeMs;
    return { reader: await maxmind.open<T>(path), mtimeMs };
  } catch {
    return null;
  }
}

function changed(opened: Opened<AsnResponse | CountryResponse> | undefined, path: string): boolean {
  if (opened === undefined) return true;
  try {
    const exists = existsSync(path);
    if (!opened) return exists;
    return !exists || statSync(path).mtimeMs !== opened.mtimeMs;
  } catch {
    return false;
  }
}

async function readers(paths: { country: string; asn: string }) {
  const current = (state.__ingressiGeoipLookup ??= { country: undefined, asn: undefined, checkedAt: 0 });
  if (Date.now() - current.checkedAt >= RECHECK_MS || current.country === undefined || current.asn === undefined) {
    if (changed(current.country, paths.country)) current.country = await open<CountryResponse>(paths.country);
    if (changed(current.asn, paths.asn)) current.asn = await open<AsnResponse>(paths.asn);
    current.checkedAt = Date.now();
  }
  return current;
}

/** Strips an IPv4-mapped IPv6 prefix and an IPv6 zone. */
export function normalizeIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  let value = ip.trim();
  if (value.startsWith("::ffff:") && isIPv4(value.slice(7))) value = value.slice(7);
  value = value.split("%")[0];
  return isIPv4(value) || isIPv6(value) ? value : null;
}

/** The approximate place of `ip`, or null for an invalid address or when neither database knows it. */
export async function lookupIpLocation(
  ip: string | null | undefined,
  paths: { country: string; asn: string } = { country: COUNTRY_DATABASE_PATH, asn: ASN_DATABASE_PATH }
): Promise<IpLocation | null> {
  const address = normalizeIp(ip);
  if (!address) return null;
  const { country, asn } = await readers(paths);
  let countryRecord: CountryResponse | null;
  let asnRecord: AsnResponse | null;
  try {
    countryRecord = country?.reader.get(address) ?? null;
  } catch {
    countryRecord = null;
  }
  try {
    asnRecord = asn?.reader.get(address) ?? null;
  } catch {
    asnRecord = null;
  }
  const countryCode = countryRecord?.country?.iso_code ?? countryRecord?.registered_country?.iso_code ?? null;
  const countryName = countryRecord?.country?.names?.en ?? countryRecord?.registered_country?.names?.en ?? null;
  const asNumber = asnRecord?.autonomous_system_number ?? null;
  const operator = asnRecord?.autonomous_system_organization ? String(asnRecord.autonomous_system_organization).slice(0, 120) : null;
  if (!countryCode && !asNumber) return null;
  return { countryCode, country: countryName, asn: asNumber, network: operator };
}

/** For tests: forget the opened databases. */
export function resetGeoipLookupForTests(): void {
  delete state.__ingressiGeoipLookup;
}
