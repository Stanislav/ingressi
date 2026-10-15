/**
 * Why Caddy could not get a certificate: the last error per domain, read from
 * /logs/tls-issuance.log, a log Caddy writes for this purpose (src/lib/caddy.ts,
 * `tls_issuance`: the ERROR lines of the loggers that obtain and renew
 * certificates). Caddy's admin API has no endpoint for these errors, and the
 * dashboard has no access to the container's output.
 *
 * What Caddy logs is not fit to show as it is: ACME errors quote the order and
 * account URLs, DNS provider errors can quote the request that failed (with an
 * API key in its address, for some providers), and any of it can name
 * addresses or e-mail addresses. Everything that leaves this module has been
 * through sanitizeIssuanceMessage:
 *   - the DNS provider credentials stored here are replaced wherever they
 *     appear, also percent-encoded;
 *   - URLs are cut down to scheme and host, and the "(order=…)" and "(ca=…)"
 *     parts ACME clients append are removed;
 *   - e-mail addresses and IP addresses are replaced;
 *   - long opaque tokens (keys, request IDs) are replaced;
 *   - control characters are dropped and the text is cut to MAX_MESSAGE_LENGTH.
 * The raw file stays readable by the container users that already read
 * Caddy's other logs (0640, group of Caddy), and is rotated like them.
 *
 * Only the end of the file is read (MAX_READ_BYTES), the result is cached
 * until the file changes, and a missing or unreadable file means no errors.
 */
import { open, stat } from "node:fs/promises";
import { decryptProviderCredentials } from "./dns-providers";
import { getDnsProviderSettings } from "./settings";

export const TLS_ISSUANCE_LOG = "/logs/tls-issuance.log";

/** The loggers whose errors the file holds (src/lib/caddy.ts includes the same). */
export const TLS_ISSUANCE_LOGGERS = ["tls.obtain", "tls.renew", "tls.issuance.acme"] as const;

const MAX_READ_BYTES = 512 * 1024;
const MAX_MESSAGE_LENGTH = 300;
/** Longer lines are not read, and longer text is cut before the patterns run over it (they are not linear on megabytes). */
const MAX_LINE_LENGTH = 100_000;
const MAX_WORKING_LENGTH = 4_000;
/** Credentials shorter than this would blank out ordinary words. */
const MIN_SECRET_LENGTH = 6;

export type IssuanceError = {
  /** When Caddy logged it (ISO 8601). */
  at: string;
  /** Sanitized text. */
  message: string;
};

/** One error line of the file, before sanitizing. */
export type RawIssuanceError = { identifier: string; at: string; error: string };

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * An error Caddy logged while obtaining or renewing the certificate of one
 * name, or null for any other line (information, lock housekeeping, other
 * loggers, text that is not JSON).
 */
export function parseIssuanceLine(line: string): RawIssuanceError | null {
  if (line.length > MAX_LINE_LENGTH) return null;
  let entry: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(line);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    entry = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  if (entry.level !== "error") return null;
  const logger = asString(entry.logger);
  if (!logger || !TLS_ISSUANCE_LOGGERS.some((name) => logger === name || logger.startsWith(`${name}.`))) return null;
  // Housekeeping around the lock files names paths inside the container.
  if (/lock/i.test(String(entry.msg ?? ""))) return null;
  const identifiers = Array.isArray(entry.identifiers) ? entry.identifiers : [];
  const identifier = asString(entry.identifier) ?? asString(identifiers[0]);
  const error = asString(entry.error);
  const ts = typeof entry.ts === "number" ? entry.ts : Number.NaN;
  if (!identifier || !error || Number.isNaN(ts)) return null;
  const at = new Date(ts * 1000);
  if (Number.isNaN(at.getTime())) return null;
  return { identifier: identifier.trim().toLowerCase(), at: at.toISOString(), error };
}

/** The last error of each name in `lines` (oldest first). */
export function lastErrorsOf(lines: readonly string[]): Map<string, RawIssuanceError> {
  const result = new Map<string, RawIssuanceError>();
  for (const line of lines) {
    const parsed = parseIssuanceLine(line);
    if (parsed) result.set(parsed.identifier, parsed);
  }
  return result;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Cuts a URL down to scheme and host: path, query and credentials can hold keys and IDs. */
function urlHost(url: string): string {
  const match = url.match(/^(https?):\/\/(?:[^/@\s]*@)?(\[[^\]]*\]|[^/?#\s:]+)/i);
  return match ? `${match[1].toLowerCase()}://${match[2]}` : "[url]";
}

/**
 * The text of an error as it may be shown: see the header of this file.
 * `secrets` are the values to blank out wherever they appear.
 */
export function sanitizeIssuanceMessage(text: string, secrets: readonly string[] = []): string {
  let out = text.replace(/[\p{Cc}\u2028\u2029]+/gu, " ");
  for (const secret of [...new Set(secrets)].filter((value) => value.length >= MIN_SECRET_LENGTH).sort((a, b) => b.length - a.length)) {
    for (const form of new Set([secret, encodeURIComponent(secret), encodeURI(secret)])) {
      out = out.replace(new RegExp(escapeRegExp(form), "gi"), "[redacted]");
    }
  }
  // Cut only after the credentials are gone, so a cut cannot leave half of one behind.
  if (out.length > MAX_WORKING_LENGTH) out = out.slice(0, MAX_WORKING_LENGTH);
  // "(order=https://…)" and "(ca=https://…)": the order and the account are named by their URLs.
  out = out.replace(/\s*\((?:order|ca|account|url|directory)=[^)]*\)/gi, "");
  out = out.replace(/https?:\/\/[^\s"'<>]*[^\s"'<>.,;:!?)\]]/gi, (url) => urlHost(url));
  out = out.replace(/[^\s@"'<>()[\],;]+@[^\s@"'<>()[\],;]+\.[a-z]{2,}/gi, "[email]");
  out = out.replace(/\[[0-9a-f:.]*:[0-9a-f:.]*\](?::\d+)?/gi, "[address]");
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, "[address]");
  out = out.replace(/(?<![\w:.])(?:(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})(?![\w:.])/gi, "[address]");
  // Keys and request IDs: long, with letters and digits, and no dot (names have dots).
  out = out.replace(/[A-Za-z0-9_+/=-]{24,}/g, (token) => (/[A-Za-z]/.test(token) && /\d/.test(token) ? "[redacted]" : token));
  out = out.replace(/\s+/g, " ").trim();
  return out.length > MAX_MESSAGE_LENGTH ? `${out.slice(0, MAX_MESSAGE_LENGTH - 1).trimEnd()}…` : out;
}

/** The DNS provider credential values stored here, to be blanked out of the text. */
async function storedSecrets(): Promise<string[]> {
  let settings: Awaited<ReturnType<typeof getDnsProviderSettings>>;
  try {
    settings = await getDnsProviderSettings();
  } catch {
    return [];
  }
  const values: string[] = [];
  for (const [provider, credentials] of Object.entries(settings?.providers ?? {})) {
    try {
      for (const value of Object.values(decryptProviderCredentials(provider, credentials))) {
        if (typeof value === "string") values.push(value);
      }
    } catch {
      // A credential that cannot be decrypted cannot appear in the text either.
    }
  }
  return values;
}

type Cached = { file: string; size: number; mtimeMs: number; errors: Map<string, RawIssuanceError> };
let cache: Cached | null = null;

/** The end of `file` as whole lines (a first partial line is dropped when the read starts mid-file). */
async function readTail(file: string, size: number): Promise<string[]> {
  const handle = await open(file, "r");
  try {
    const start = Math.max(0, size - MAX_READ_BYTES);
    const buffer = Buffer.alloc(size - start);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
    const lines = buffer.subarray(0, bytesRead).toString("utf8").split("\n");
    if (start > 0) lines.shift();
    return lines.filter(Boolean);
  } finally {
    await handle.close();
  }
}

async function rawErrors(file: string): Promise<Map<string, RawIssuanceError>> {
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(file);
  } catch {
    cache = null;
    return new Map();
  }
  if (cache && cache.file === file && cache.size === info.size && cache.mtimeMs === info.mtimeMs) return cache.errors;
  try {
    const errors = lastErrorsOf(await readTail(file, info.size));
    cache = { file, size: info.size, mtimeMs: info.mtimeMs, errors };
    return errors;
  } catch {
    return new Map();
  }
}

/** Forgets what was read (tests). */
export function clearIssuanceCache(): void {
  cache = null;
}

/**
 * The last error Caddy logged for each of `domains` (trimmed and lower-cased,
 * wildcards as configured), sanitized. Names without an error are left out.
 */
export async function getIssuanceErrors(domains: readonly string[], options: { file?: string } = {}): Promise<Map<string, IssuanceError>> {
  const result = new Map<string, IssuanceError>();
  const wanted = [...new Set(domains.map((domain) => domain.trim().toLowerCase()).filter(Boolean))];
  if (wanted.length === 0) return result;
  const errors = await rawErrors(options.file ?? TLS_ISSUANCE_LOG);
  const found = wanted.filter((domain) => errors.has(domain));
  if (found.length === 0) return result;
  const secrets = await storedSecrets();
  for (const domain of found) {
    const raw = errors.get(domain)!;
    const message = sanitizeIssuanceMessage(raw.error, secrets);
    if (message) result.set(domain, { at: raw.at, message });
  }
  return result;
}
