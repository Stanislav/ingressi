// SPDX-License-Identifier: Elastic-2.0
/**
 * Autonomous-system lookups for the daily digest, from the GeoLite2-ASN
 * database in the geoip-data volume (also used by the geo blocker).
 * Client addresses are looked up in this process and only the AS
 * number, organization and network range leave this module.
 */
import { existsSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";
import maxmind, { type AsnResponse } from "maxmind";

export const ASN_DATABASE_PATH = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";

export type AsnInfo = { asn: number; organization: string; /** CIDR of the routed network, e.g. "203.0.113.0/24" */ network: string };
export type AsnLookup = (ip: string) => AsnInfo | null;

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
}

function ipv6ToBigInt(ip: string): bigint | null {
  let address = ip.split("%")[0].toLowerCase();
  const embedded = /(\d+\.\d+\.\d+\.\d+)$/.exec(address);
  if (embedded) {
    const value = ipv4ToInt(embedded[1]);
    address = `${address.slice(0, -embedded[1].length)}${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...new Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  let value = BigInt(0);
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << BigInt(16)) | BigInt(parseInt(group, 16));
  }
  return value;
}

/** The network containing `ip` with the given prefix length, as CIDR; null for an invalid address. */
export function networkCidr(ip: string, prefixLength: number): string | null {
  if (isIPv4(ip)) {
    const prefix = Math.max(0, Math.min(32, prefixLength));
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (ipv4ToInt(ip) & mask) >>> 0;
    return `${[24, 16, 8, 0].map((shift) => (network >>> shift) & 0xff).join(".")}/${prefix}`;
  }
  if (isIPv6(ip)) {
    const value = ipv6ToBigInt(ip);
    if (value === null) return null;
    const prefix = Math.max(0, Math.min(128, prefixLength));
    const all = (BigInt(1) << BigInt(128)) - BigInt(1);
    const mask = prefix === 0 ? BigInt(0) : (all << BigInt(128 - prefix)) & all;
    const network = value & mask;
    const groups: string[] = [];
    for (let shift = 112; shift >= 0; shift -= 16) groups.push(((network >> BigInt(shift)) & BigInt(0xffff)).toString(16));
    return `${groups.join(":")}/${prefix}`;
  }
  return null;
}

/** Opens the ASN database, or returns null when it is missing or unreadable. */
export async function openAsnLookup(path: string = ASN_DATABASE_PATH): Promise<AsnLookup | null> {
  if (!existsSync(path)) return null;
  let reader: Awaited<ReturnType<typeof maxmind.open<AsnResponse>>>;
  try {
    reader = await maxmind.open<AsnResponse>(path);
  } catch {
    return null;
  }
  return (ip) => {
    if (!isIPv4(ip) && !isIPv6(ip)) return null;
    try {
      const [record, prefixLength] = reader.getWithPrefixLength(ip);
      if (!record?.autonomous_system_number) return null;
      const network = networkCidr(ip, prefixLength);
      if (!network) return null;
      return {
        asn: record.autonomous_system_number,
        organization: String(record.autonomous_system_organization ?? "").slice(0, 120),
        network,
      };
    } catch {
      return null;
    }
  };
}
