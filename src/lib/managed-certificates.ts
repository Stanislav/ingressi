/**
 * Certificates Caddy obtains and renews itself: proxy hosts without an
 * imported certificate (ACME, or Caddy's internal CA for internal names) and
 * hosts that use a "managed" certificate entry (ACME with DNS-01 options).
 * The one reader of them: the certificates page (getManagedCertificateExpiry)
 * and alerting, the overview, the setup checklist and compliance
 * (getManagedCertificates) share its probe, cache, concurrency limit and
 * timeout.
 *
 * Source: a TLS handshake to Caddy's HTTPS listener with each domain as SNI,
 * reading the certificate Caddy presents. This is what clients get, and it
 * works however the certificates are stored: Caddy's storage volume is not
 * mounted into the web container, the shared Redis/Valkey storage of
 * ee/high-availability is not a file system at all, and Caddy's admin API
 * has no endpoint that lists managed certificates. Only the certificate's
 * metadata is read; nothing is sent after the handshake.
 *
 * - The address is CADDY_TLS_ADDRESS (host:port) or the host of
 *   CADDY_API_URL on port 443, the address the web container reaches Caddy
 *   at; CADDY_TLS_ADDRESS=off turns the checks off (the tests do). The
 *   handshake does not verify the chain (a staging or internal CA is still
 *   reported); coverage of the name is checked separately.
 * - A wildcard domain is probed as `tls-check.<domain>`.
 * - Caddy renews a certificate when a third of its lifetime is left
 *   (certmagic's default renewal window). Past that point plus one day of
 *   retries the renewal counts as overdue, which means it is failing.
 * - Caddy answers a name it has no certificate for with a TLS
 *   "internal error" alert: reported as "missing". Any other TLS error (for
 *   example an mTLS host that demands a client certificate under TLS 1.2) is
 *   reported as "error" and never treated as a missing certificate.
 * - Only the Caddy this node talks to is probed; in a fleet each node probes
 *   its own.
 *
 * Handshakes are bounded: at most CONCURRENCY at a time across every caller,
 * each with a PROBE_TIMEOUT_MS timeout, and one per name at a time (callers
 * asking for a name being probed share the handshake). Results are cached
 * per name (valid ones for 30 minutes, problems for 5).
 */
import tls from "node:tls";
import { isIP } from "node:net";
import { X509Certificate } from "node:crypto";
import { and, eq, inArray, isNull, or } from "drizzle-orm";
import { appDb } from "./db";
import { certificates, proxyHosts } from "./db/schema";
import { config } from "./config";
import { parseStoredTags } from "./host-tags";
import { scopeTagsFor, tagsInScope, type Access } from "./permissions";

export const MANAGED_CERT_STATES = ["valid", "renewal_due", "renewal_overdue", "expired", "missing", "mismatch", "error"] as const;
export type ManagedCertificateState = (typeof MANAGED_CERT_STATES)[number];

export type ManagedCertificateStatus = {
  /** The domain as configured on the host (may be a wildcard). */
  domain: string;
  /** The name sent as SNI. */
  servername: string;
  proxyHosts: { id: number; name: string }[];
  /** The latest time one of those hosts was saved (a new name may still be waiting for its first certificate). */
  changedAt: string | null;
  state: ManagedCertificateState;
  validFrom: string | null;
  validTo: string | null;
  /** Whole days until validTo (negative once expired). */
  daysLeft: number | null;
  /** When Caddy starts renewing it: validTo minus a third of its lifetime. */
  renewsAt: string | null;
  issuer: string | null;
  fingerprint256: string | null;
  /** A short, application-authored reason for "missing", "mismatch" and "error". */
  error: string | null;
  checkedAt: string;
};

export type ManagedCertificateReport = {
  /** False when Caddy's HTTPS listener could not be reached (or nothing was probed yet). */
  available: boolean;
  reason: string | null;
  certificates: ManagedCertificateStatus[];
  /** Domains not probed yet (only with cachedOnly). */
  unchecked: number;
};

/** The certificate Caddy serves for one domain, as the certificates page shows it. */
export type ManagedCertificateExpiry = {
  /** The domain asked for, trimmed and lower-cased. */
  domain: string;
  /** Start of the validity period (ISO 8601). */
  validFrom: string;
  /** End of the validity period (ISO 8601). */
  validTo: string;
  /** The issuing organisation ("Let's Encrypt"), or its common name. */
  issuer: string | null;
  /** "ECDSA P-256", "RSA 2048". */
  keyType: string | null;
  /** When the certificate was read (ISO 8601). */
  checkedAt: string;
};

export type ManagedCertificateExpiryOptions = {
  /**
   * How long to wait for handshakes that are not cached yet, in ms (default
   * 3000). Handshakes still running then keep going and fill the cache for
   * the next call; their domains are missing from this result (or show the
   * previous reading, when there is one).
   */
  waitMs?: number;
};

/** What one handshake returned. */
export type ProbeResult =
  | { kind: "certificate"; pem: string }
  | { kind: "missing" }
  | { kind: "tls_error"; code: string }
  | { kind: "unreachable"; code: string };

export type ProbeFn = (servername: string) => Promise<ProbeResult>;

const DAY_MS = 24 * 60 * 60 * 1000;
const PROBE_TIMEOUT_MS = 5_000;
const CONCURRENCY = 6;
const MAX_DOMAINS = 1000;
const MAX_CACHED = 5000;
const VALID_TTL_MS = 30 * 60 * 1000;
const PROBLEM_TTL_MS = 5 * 60 * 1000;
const DEFAULT_WAIT_MS = 3000;
/** Retries Caddy gets after the renewal point before the renewal counts as failing. */
const RENEWAL_GRACE_MS = DAY_MS;
const WILDCARD_LABEL = "tls-check";
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/** One handshake's result for a name, when it was made and how long it stays fresh. */
type CacheEntry = { result: ProbeResult; at: number; ttl: number };

type ProbeState = {
  entries: Map<string, CacheEntry>;
  inFlight: Map<string, Promise<CacheEntry>>;
  /** Handshakes running now, and the ones waiting for a slot. */
  active: number;
  waiting: Array<() => void>;
  /** The background refresh of getManagedCertificates({ cachedOnly }). */
  refreshing: Promise<void> | null;
  probe: ProbeFn | null;
  /** Bumped when the cache is cleared, so handshakes started before do not refill it. */
  generation: number;
};

// On globalThis so the route handlers, server components and the alert
// evaluator share it even where the bundler loads this module more than once.
const store = globalThis as typeof globalThis & { __ingressiCaddyTlsProbe?: ProbeState };
const state: ProbeState = (store.__ingressiCaddyTlsProbe ??= {
  entries: new Map<string, CacheEntry>(),
  inFlight: new Map<string, Promise<CacheEntry>>(),
  active: 0,
  waiting: [] as Array<() => void>,
  refreshing: null,
  probe: null,
  generation: 0,
});

/** Where Caddy's HTTPS listener is, as the web container reaches it; null when the checks are off or the address is invalid. */
export function caddyTlsAddress(): { host: string; port: number } | null {
  const explicit = process.env.CADDY_TLS_ADDRESS?.trim();
  if (explicit && /^(off|none|false|disabled)$/i.test(explicit)) return null;
  if (explicit) {
    const match = explicit.match(/^\[?([^\]]+?)\]?:(\d{1,5})$/);
    if (match) {
      const port = Number(match[2]);
      return port > 0 && port < 65536 ? { host: match[1], port } : null;
    }
    return { host: explicit.replace(/^\[|\]$/g, ""), port: 443 };
  }
  try {
    return { host: new URL(config.caddyApiUrl).hostname.replace(/^\[|\]$/g, ""), port: 443 };
  } catch {
    return { host: "caddy", port: 443 };
  }
}

const UNREACHABLE_CODES = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "ECONNRESET", "TIMEOUT"]);

/** The default probe: one TLS handshake to Caddy, the peer certificate as PEM. */
export const tlsProbe: ProbeFn = (servername) =>
  new Promise((resolve) => {
    const address = caddyTlsAddress();
    if (!address) {
      resolve({ kind: "unreachable", code: "DISABLED" });
      return;
    }
    const { host, port } = address;
    let settled = false;
    const finish = (result: ProbeResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const socket = tls.connect({
      host,
      port,
      servername,
      // The certificate is read, never trusted: its chain may be private
      // (an internal ACME CA) and nothing is exchanged after the handshake.
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
      timeout: PROBE_TIMEOUT_MS,
    });
    socket.setTimeout(PROBE_TIMEOUT_MS, () => finish({ kind: "unreachable", code: "TIMEOUT" }));
    socket.once("secureConnect", () => {
      try {
        // getPeerX509Certificate where the runtime has it; the DER bytes otherwise (Bun and Node both give them).
        const peer = typeof socket.getPeerX509Certificate === "function" ? socket.getPeerX509Certificate() : undefined;
        const raw = peer ? null : socket.getPeerCertificate(true)?.raw;
        const pem = peer ? peer.toString() : raw ? new X509Certificate(raw).toString() : null;
        finish(pem ? { kind: "certificate", pem } : { kind: "missing" });
      } catch {
        finish({ kind: "tls_error", code: "UNREADABLE_CERTIFICATE" });
      }
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      const code = typeof error.code === "string" ? error.code.slice(0, 64) : "ERROR";
      if (UNREACHABLE_CODES.has(code)) finish({ kind: "unreachable", code });
      // Caddy has no certificate for the name: "no certificate available" as an internal_error alert.
      else if (/ALERT_INTERNAL_ERROR/i.test(code) || /alert internal error/i.test(String(error.message))) finish({ kind: "missing" });
      else finish({ kind: "tls_error", code });
    });
    // Closed before the handshake finished, without an error.
    socket.once("close", () => finish({ kind: "tls_error", code: "CLOSED" }));
  });

/** Replaces the probe (tests); null restores the TLS handshake. Clears the cache. */
export function setManagedCertificateProbeForTests(probe: ProbeFn | null): void {
  state.probe = probe;
  clearCertificateExpiryCache();
}

/** Forgets every cached result (tests, or after Caddy's certificates were replaced). */
export function clearCertificateExpiryCache(): void {
  state.generation++;
  state.entries.clear();
  state.inFlight.clear();
  state.refreshing = null;
}

function probeFn(): ProbeFn {
  return state.probe ?? tlsProbe;
}

function parseJsonList(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

/** The SNI name to probe a configured domain with, or null when it cannot be probed. */
export function probeName(domain: string): string | null {
  const trimmed = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!trimmed || isIP(trimmed)) return null;
  const name = trimmed.startsWith("*.") ? `${WILDCARD_LABEL}.${trimmed.slice(2)}` : trimmed;
  return HOSTNAME.test(name) ? name : null;
}

export type ManagedDomain = { domain: string; servername: string; proxyHosts: { id: number; name: string }[]; changedAt: string | null };

/** Domains of enabled proxy hosts whose certificate Caddy manages. */
export async function listManagedDomains(): Promise<ManagedDomain[]> {
  const rows = await appDb
    .select({ id: proxyHosts.id, name: proxyHosts.name, domains: proxyHosts.domains, updatedAt: proxyHosts.updatedAt, certificateType: certificates.type })
    .from(proxyHosts)
    .leftJoin(certificates, eq(certificates.id, proxyHosts.certificateId))
    .where(and(eq(proxyHosts.enabled, true), or(isNull(proxyHosts.certificateId), eq(certificates.type, "managed"))))
    // A domain's hosts (and the spelling it is shown with) in a stable order.
    .orderBy(proxyHosts.id);
  const byName = new Map<string, ManagedDomain>();
  for (const row of rows) {
    if (row.certificateType !== null && row.certificateType !== "managed") continue;
    for (const domain of parseJsonList(row.domains)) {
      const servername = probeName(domain);
      if (!servername) continue;
      const entry = byName.get(servername) ?? { domain: domain.trim().toLowerCase(), servername, proxyHosts: [], changedAt: null };
      if (!entry.proxyHosts.some((host) => host.id === row.id)) entry.proxyHosts.push({ id: row.id, name: row.name });
      const updatedAt = Number.isNaN(Date.parse(row.updatedAt)) ? null : new Date(row.updatedAt).toISOString();
      if (updatedAt && (!entry.changedAt || updatedAt > entry.changedAt)) entry.changedAt = updatedAt;
      byName.set(servername, entry);
    }
  }
  return [...byName.values()].sort((a, b) => a.servername.localeCompare(b.servername)).slice(0, MAX_DOMAINS);
}

function issuerName(cert: X509Certificate): string | null {
  const issuer = cert.issuer ?? "";
  const value = issuer.match(/O=([^\n,]+)/)?.[1] ?? issuer.match(/CN=([^\n,]+)/)?.[1] ?? null;
  return value ? value.trim().replace(/\p{Cc}+/gu, " ").slice(0, 120) : null;
}

const NIST_CURVES: Record<string, string> = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };

/** "ECDSA P-256", "RSA 2048", "Ed25519": the certificate's key, as the certificates page names it. */
export function certificateKeyType(cert: X509Certificate): string | null {
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === "ec") {
    const curve = details?.namedCurve;
    return curve ? `ECDSA ${NIST_CURVES[curve] ?? curve}` : "ECDSA";
  }
  if (key.asymmetricKeyType === "rsa" || key.asymmetricKeyType === "rsa-pss") {
    return details?.modulusLength ? `RSA ${details.modulusLength}` : "RSA";
  }
  if (key.asymmetricKeyType === "ed25519") return "Ed25519";
  return key.asymmetricKeyType ? key.asymmetricKeyType.toUpperCase() : null;
}

/** Turns one probe result into a status (pure; exported for tests). */
export function classifyProbe(domain: ManagedDomain, result: ProbeResult, now: Date): ManagedCertificateStatus {
  const base: ManagedCertificateStatus = {
    domain: domain.domain,
    servername: domain.servername,
    proxyHosts: domain.proxyHosts,
    changedAt: domain.changedAt,
    state: "error",
    validFrom: null,
    validTo: null,
    daysLeft: null,
    renewsAt: null,
    issuer: null,
    fingerprint256: null,
    error: null,
    checkedAt: now.toISOString(),
  };
  if (result.kind === "missing") return { ...base, state: "missing", error: "Caddy has no certificate for this name" };
  if (result.kind === "unreachable") return { ...base, state: "error", error: `Caddy's HTTPS port could not be reached (${result.code})` };
  if (result.kind === "tls_error") return { ...base, state: "error", error: `The TLS handshake failed (${result.code})` };
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(result.pem);
  } catch {
    return { ...base, state: "error", error: "Caddy presented a certificate that could not be read" };
  }
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validTo.getTime())) {
    return { ...base, state: "error", error: "Caddy presented a certificate without readable dates" };
  }
  const lifetime = Math.max(0, validTo.getTime() - validFrom.getTime());
  const renewsAt = new Date(validTo.getTime() - lifetime / 3);
  const status: ManagedCertificateStatus = {
    ...base,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysLeft: Math.floor((validTo.getTime() - now.getTime()) / DAY_MS),
    renewsAt: renewsAt.toISOString(),
    issuer: issuerName(cert),
    fingerprint256: cert.fingerprint256,
  };
  if (cert.checkHost(domain.servername) === undefined) {
    return { ...status, state: "mismatch", error: "The certificate Caddy presents does not cover this name" };
  }
  if (now.getTime() >= validTo.getTime()) return { ...status, state: "expired" };
  if (now.getTime() >= renewsAt.getTime() + RENEWAL_GRACE_MS) return { ...status, state: "renewal_overdue" };
  if (now.getTime() >= renewsAt.getTime()) return { ...status, state: "renewal_due" };
  return { ...status, state: "valid" };
}

/** A name with no hosts, for classifying a cached result on its own. */
function bareDomain(servername: string): ManagedDomain {
  return { domain: servername, servername, proxyHosts: [], changedAt: null };
}

// ── The shared probe: one handshake per name at a time, CONCURRENCY at most ──

function acquire(): Promise<void> {
  if (state.active < CONCURRENCY) {
    state.active++;
    return Promise.resolve();
  }
  return new Promise((resolve) => state.waiting.push(resolve));
}

/** Hands the slot to the next waiting handshake, or frees it. */
function release() {
  const next = state.waiting.shift();
  if (next) next();
  else state.active--;
}

function remember(servername: string, entry: CacheEntry) {
  state.entries.delete(servername);
  state.entries.set(servername, entry);
  while (state.entries.size > MAX_CACHED) {
    const oldest = state.entries.keys().next().value;
    if (oldest === undefined) break;
    state.entries.delete(oldest);
  }
}

/** Probes `servername` now (or joins the handshake already running for it) and caches the result. */
function probeServername(servername: string, now: Date): Promise<CacheEntry> {
  const running = state.inFlight.get(servername);
  if (running) return running;
  const generation = state.generation;
  const promise = (async (): Promise<CacheEntry> => {
    await acquire();
    let result: ProbeResult;
    try {
      result = await probeFn()(servername);
    } catch {
      result = { kind: "tls_error", code: "PROBE_FAILED" };
    } finally {
      release();
    }
    const status = classifyProbe(bareDomain(servername), result, now);
    const ttl = status.state === "valid" || status.state === "renewal_due" ? VALID_TTL_MS : PROBLEM_TTL_MS;
    const entry: CacheEntry = { result, at: now.getTime(), ttl };
    if (state.generation === generation) remember(servername, entry);
    return entry;
  })().finally(() => {
    if (state.inFlight.get(servername) === promise) state.inFlight.delete(servername);
  });
  state.inFlight.set(servername, promise);
  return promise;
}

function stale(entry: CacheEntry | undefined, now: Date, maxAgeMs?: number): boolean {
  if (!entry) return true;
  return now.getTime() - entry.at >= (maxAgeMs ?? entry.ttl);
}

async function probeAll(servernames: string[], now: Date): Promise<void> {
  await Promise.all(servernames.map((servername) => probeServername(servername, now)));
}

// ── For the certificates page ──

/** The certificate in a cached result, when it names `servername`. */
function expiryOf(domain: string, servername: string, entry: CacheEntry): ManagedCertificateExpiry | null {
  if (entry.result.kind !== "certificate") return null;
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(entry.result.pem);
  } catch {
    return null;
  }
  // A certificate that does not name the domain (a fallback, another host's)
  // says nothing about the domain's own certificate.
  if (cert.checkHost(servername) === undefined) return null;
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  if (Number.isNaN(validTo.getTime()) || Number.isNaN(validFrom.getTime())) return null;
  return {
    domain,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    issuer: issuerName(cert),
    keyType: certificateKeyType(cert),
    checkedAt: new Date(entry.at).toISOString(),
  };
}

/**
 * What the last handshake for a domain showed. A domain with no reading at all
 * has not been asked yet (the first handshake did not finish within `waitMs`),
 * or cannot be asked for (an IP address).
 */
export type ManagedCertificateReading =
  /** Caddy serves a certificate that names the domain. */
  | { kind: "served"; expiry: ManagedCertificateExpiry }
  /** Caddy answered without a certificate for the name (not obtained yet or failing), or with one that does not name it. */
  | { kind: "none"; checkedAt: string }
  /** The handshake did not work (Caddy unreachable, a TLS error): says nothing about the certificate. */
  | { kind: "unavailable"; checkedAt: string };

/**
 * What Caddy showed for `domains`, keyed by the domain (trimmed and
 * lower-cased). Domains without a reading are left out; see
 * ManagedCertificateReading.
 */
export async function getManagedCertificateReadings(
  domains: readonly string[],
  options: ManagedCertificateExpiryOptions = {}
): Promise<Map<string, ManagedCertificateReading>> {
  const result = new Map<string, ManagedCertificateReading>();
  // Checks turned off: nothing to read (unless a test replaced the probe).
  if (!state.probe && !caddyTlsAddress()) return result;
  const now = new Date();
  const names = new Map<string, string>();
  for (const domain of domains) {
    const key = domain.trim().toLowerCase();
    const servername = probeName(key);
    if (servername && !names.has(key)) names.set(key, servername);
  }
  if (names.size === 0) return result;

  const due = [...new Set([...names.values()].filter((servername) => stale(state.entries.get(servername), now)))];
  if (due.length > 0) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      probeAll(due, now).catch(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, options.waitMs ?? DEFAULT_WAIT_MS);
        timer.unref?.();
      }),
    ]);
    if (timer) clearTimeout(timer);
  }

  for (const [domain, servername] of names) {
    const entry = state.entries.get(servername);
    if (!entry) continue;
    const checkedAt = new Date(entry.at).toISOString();
    if (entry.result.kind === "certificate") {
      const expiry = expiryOf(domain, servername, entry);
      result.set(domain, expiry ? { kind: "served", expiry } : { kind: "none", checkedAt });
    } else if (entry.result.kind === "missing") {
      result.set(domain, { kind: "none", checkedAt });
    } else {
      result.set(domain, { kind: "unavailable", checkedAt });
    }
  }
  return result;
}

/**
 * The certificates Caddy serves for `domains`, keyed by the domain (trimmed
 * and lower-cased). A domain is missing when Caddy serves no certificate for
 * it (not obtained yet, host disabled, Caddy unreachable), when the
 * certificate it serves does not name it, when the name cannot be asked for
 * (an IP address) or when its first handshake did not finish within `waitMs`.
 */
export async function getManagedCertificateExpiry(
  domains: readonly string[],
  options: ManagedCertificateExpiryOptions = {}
): Promise<Map<string, ManagedCertificateExpiry>> {
  const result = new Map<string, ManagedCertificateExpiry>();
  for (const [domain, reading] of await getManagedCertificateReadings(domains, options)) {
    if (reading.kind === "served") result.set(domain, reading.expiry);
  }
  return result;
}

// ── For alerting, the overview, the setup checklist and compliance ──

function report(domains: ManagedDomain[], now: Date): ManagedCertificateReport {
  const certificatesFound: ManagedCertificateStatus[] = [];
  let unchecked = 0;
  let unreachable = 0;
  for (const domain of domains) {
    const entry = state.entries.get(domain.servername);
    if (!entry) {
      unchecked += 1;
      continue;
    }
    if (entry.result.kind === "unreachable") unreachable += 1;
    // The hosts using a name can change between probes; the state is as of now.
    certificatesFound.push({ ...classifyProbe(domain, entry.result, now), checkedAt: new Date(entry.at).toISOString() });
  }
  const checked = certificatesFound.length;
  const available = checked > 0 && unreachable < checked;
  return {
    available: domains.length === 0 ? true : available,
    reason:
      domains.length === 0
        ? null
        : checked === 0
          ? "Caddy's certificates have not been checked yet"
          : !available
            ? "Caddy's HTTPS port could not be reached from the dashboard"
            : null,
    certificates: available ? certificatesFound : [],
    unchecked,
  };
}

/**
 * The certificates Caddy manages for enabled proxy hosts. Probes names
 * whose cached result is older than its TTL (or `maxAgeMs`). With
 * `cachedOnly`, returns at once with what is cached and refreshes in the
 * background (for page loads).
 */
export async function getManagedCertificates(options: { now?: Date; maxAgeMs?: number; cachedOnly?: boolean } = {}): Promise<ManagedCertificateReport> {
  const now = options.now ?? new Date();
  const domains = await listManagedDomains();
  const due = domains.filter((domain) => stale(state.entries.get(domain.servername), now, options.maxAgeMs)).map((domain) => domain.servername);
  if (due.length > 0) {
    if (options.cachedOnly) {
      if (!state.refreshing) {
        const refreshing: Promise<void> = probeAll(due, now)
          .catch(() => undefined)
          .finally(() => {
            if (state.refreshing === refreshing) state.refreshing = null;
          });
        state.refreshing = refreshing;
      }
    } else {
      await probeAll(due, now);
    }
  }
  return report(domains, now);
}

/** Problems worth someone's attention (pure). */
export function isManagedCertificateProblem(status: ManagedCertificateStatus): boolean {
  return status.state === "expired" || status.state === "renewal_overdue" || status.state === "missing" || status.state === "mismatch";
}

/**
 * The statuses `access` may see: those of proxy hosts within its tag scope
 * (certificates area), with the other hosts left out of each status.
 */
export async function filterManagedCertificatesForAccess(
  statuses: ManagedCertificateStatus[],
  access: Access
): Promise<ManagedCertificateStatus[]> {
  const scope = scopeTagsFor(access, "certificates");
  if (scope === null) return statuses;
  const ids = [...new Set(statuses.flatMap((status) => status.proxyHosts.map((host) => host.id)))];
  if (ids.length === 0) return [];
  const rows = await appDb
    .select({ id: proxyHosts.id, tags: proxyHosts.tags })
    .from(proxyHosts)
    .where(inArray(proxyHosts.id, ids));
  const visible = new Set(
    rows
      .filter((row) => tagsInScope(parseStoredTags(row.tags), scope))
      .map((row) => row.id)
  );
  return statuses
    .map((status) => ({ ...status, proxyHosts: status.proxyHosts.filter((host) => visible.has(host.id)) }))
    .filter((status) => status.proxyHosts.length > 0);
}
