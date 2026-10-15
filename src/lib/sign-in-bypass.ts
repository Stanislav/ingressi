/**
 * Addresses that skip sign-in on a proxy host: requests from them reach the
 * upstream without the forward-auth check (the built-in sign-in, Authentik or
 * generic forward auth), while everything else on the host still applies (WAF,
 * rate limits, access list, path blocks). Caddy JSON is built in caddy.ts.
 *
 * A bad entry must never widen the bypass: input is rejected with a message
 * naming it, and what is read back from storage keeps only entries that parse
 * (an entry nobody can read bypasses nobody). A range that matches every
 * address is refused, since it would turn sign-in off.
 *
 * Pure: no database and no Node built-ins, so the dashboard validates input
 * with the same code as the server.
 */
import { ApiValidationError } from "./api-errors";
import { PRIVATE_RANGES_VALUE, ipRangeContains, parseIpRange, type ParsedIpRange } from "./access-list-rules";

export const MAX_BYPASS_SOURCES = 100;

/** The text of an entry as an error message may show it. */
function shown(text: string): string {
  return text.length > 64 ? `${text.slice(0, 61)}...` : text;
}

/** One entry, normalized (a range is stored as its network address), or what is wrong with it. */
export function normalizeBypassSource(raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  if (text.toLowerCase() === PRIVATE_RANGES_VALUE) return { value: PRIVATE_RANGES_VALUE };
  const range = parseIpRange(text);
  if (!range) return { error: `"${shown(text)}" is not an IP address, a CIDR range or private_ranges` };
  if (range.prefix === 0) return { error: `"${shown(text)}" matches every address; turn sign-in off instead` };
  return { value: range.text };
}

/**
 * The entries of a request or form: an array of strings, or one string
 * separated by commas, spaces or newlines. Deduplicated; throws a 400 naming
 * the first bad entry.
 */
export function normalizeBypassSources(input: unknown, label = "bypassSources"): string[] {
  if (input === undefined || input === null) return [];
  const items: unknown = typeof input === "string" ? input.split(/[\s,]+/) : input;
  if (!Array.isArray(items)) throw new ApiValidationError(`${label} must be an array of IP addresses or CIDR ranges`);
  if (items.length > MAX_BYPASS_SOURCES * 10) {
    throw new ApiValidationError(`${label} can hold at most ${MAX_BYPASS_SOURCES} entries`);
  }
  const values: string[] = [];
  const seen = new Set<string>();
  items.forEach((item, index) => {
    if (typeof item !== "string") throw new ApiValidationError(`${label}[${index}] must be a string`);
    if (!item.trim()) return;
    const result = normalizeBypassSource(item);
    if ("error" in result) throw new ApiValidationError(`${label}: ${result.error}`);
    if (seen.has(result.value)) return;
    seen.add(result.value);
    values.push(result.value);
  });
  if (values.length > MAX_BYPASS_SOURCES) {
    throw new ApiValidationError(`${label} can hold at most ${MAX_BYPASS_SOURCES} entries`);
  }
  return values;
}

/** What storage holds, for use: the entries that are valid, normalized and deduplicated; the rest are dropped. */
export function readBypassSources(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const values: string[] = [];
  const seen = new Set<string>();
  for (const item of input) {
    if (typeof item !== "string") continue;
    const result = normalizeBypassSource(item);
    if ("error" in result || seen.has(result.value)) continue;
    seen.add(result.value);
    values.push(result.value);
    if (values.length >= MAX_BYPASS_SOURCES) break;
  }
  return values;
}

const PRIVATE_NETWORKS: readonly ParsedIpRange[] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8", "::1/128"]
  .map((network) => parseIpRange(network))
  .filter((range): range is ParsedIpRange => range !== null);

/**
 * Whether any entry is, or overlaps, a private network (private_ranges, 10/8,
 * a /24 of 192.168...). Those are the addresses a proxy, a CDN or Docker's own
 * port proxy in front of Caddy presents instead of the visitor's.
 */
export function touchesPrivateNetworks(entries: readonly string[]): boolean {
  return entries.some((entry) => {
    if (entry.trim().toLowerCase() === PRIVATE_RANGES_VALUE) return true;
    const range = parseIpRange(entry);
    return range !== null && PRIVATE_NETWORKS.some((network) => ipRangeContains(network, range) || ipRangeContains(range, network));
  });
}
