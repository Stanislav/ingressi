/**
 * Fills in the proxy hosts list and a host's page (src/lib/proxy-host-view.ts)
 * for one reader: traffic of the last 24 hours and traffic signals (with
 * analytics:read), certificates (with certificates:read), changes waiting
 * for approval, and what protects each host once its settings and the
 * global ones are combined.
 *
 * The caller passes only hosts the reader may see (its tag scope). Each
 * source fails on its own: a ClickHouse or certificate check that fails
 * leaves its columns empty instead of failing the page.
 */
import { and, eq, inArray } from "drizzle-orm";
import { appDb } from "./db";
import { changeRequests } from "./db/schema";
import { can, type Access } from "./permissions";
import type { ProxyHost } from "./models/proxy-hosts";
import { getGeoBlockSettings, getRateLimitSettings, getWafSettings, type GeoBlockSettings, type WafSettings } from "./settings";
import type { RateLimitSettings } from "./rate-limit-rules";
import { resolveEffectiveWaf } from "./caddy-waf";
import { resolveEffectiveRateLimitRules } from "./caddy-rate-limit";
import { effectiveModeOfEngine, type WafEffectiveMode } from "./waf-host-mode";
import { buildCertificateOverview } from "./certificate-overview";
import type { CertificateOverviewRow } from "./certificate-renewal";
import { queryHostSummaries, type HostSummary } from "./analytics/hosts";
import { allProxyHostDomains, trafficSignalsFor } from "./analytics/service";
import { resolveRange } from "./analytics/range";
import { normalizeDomain } from "./analytics/scope";
import type { AnalyticsStatus } from "./analytics/run";
import { isAnalyticsEnabled } from "./clickhouse/client";
import type { TrafficSignals } from "./analytics/signals";
import {
  HIGH_ERROR_RATE,
  HIGH_ERROR_RATE_MIN_REQUESTS,
  certificateAttention,
  hostState,
  protectionsOf,
  sortAttention,
  type HostAttention,
  type HostCertificate,
  type HostListRow,
  type ProtectionInput,
} from "./proxy-host-view";

export type HostInsightOptions = {
  /** Names of the access lists the reader may see, by id. */
  accessListNames?: ReadonlyMap<number, string>;
  /** How long to wait for certificate handshakes that are not cached yet, in ms. */
  certificateWaitMs?: number;
  now?: number;
};

export type HostInsights = {
  rows: HostListRow[];
  /** Whether the traffic came from ClickHouse; null when the reader may not read analytics. */
  analyticsStatus: AnalyticsStatus | null;
  /** What protects each host, by id (server side only: the host page summarises it). */
  inputs: Map<number, ProtectionInput>;
};

type Globals = { waf: WafSettings | null; geo: GeoBlockSettings | null; rateLimit: RateLimitSettings | null };

async function loadGlobals(): Promise<Globals> {
  const [waf, geo, rateLimit] = await Promise.all([
    getWafSettings().catch(() => null),
    getGeoBlockSettings().catch(() => null),
    getRateLimitSettings().catch(() => null),
  ]);
  return { waf, geo, rateLimit };
}

function uniq(values: readonly (string | number)[]): string[] {
  return [...new Set(values.map((value) => String(value).trim().toUpperCase()).filter(Boolean))];
}

/** Geo blocking that applies to the host (as resolveEffectiveGeoBlock in caddy.ts decides), summarised. */
export function effectiveGeo(global: GeoBlockSettings | null, host: Pick<ProxyHost, "geoblock" | "geoblockMode">): ProtectionInput["geo"] {
  const hostConfig = host.geoblock;
  let sources: GeoBlockSettings[];
  let fromGlobal = false;
  if (hostConfig && host.geoblockMode === "override") {
    if (!hostConfig.enabled) return null;
    sources = [hostConfig];
  } else if (hostConfig?.enabled && global?.enabled) {
    sources = [global, hostConfig];
  } else if (hostConfig?.enabled) {
    sources = [hostConfig];
  } else if (global?.enabled) {
    sources = [global];
    fromGlobal = true;
  } else {
    return null;
  }
  const blockCountries = uniq(sources.flatMap((source) => source.block_countries ?? []));
  const blockContinents = uniq(sources.flatMap((source) => source.block_continents ?? []));
  const other =
    sources.reduce((sum, source) => sum + (source.block_asns?.length ?? 0) + (source.block_cidrs?.length ?? 0) + (source.block_ips?.length ?? 0), 0);
  // Allow rules only make exceptions to block rules: without any, nothing is blocked.
  if (blockCountries.length === 0 && blockContinents.length === 0 && other === 0) return null;
  return {
    blockCountries,
    blockContinents,
    allowCountries: uniq(sources.flatMap((source) => source.allow_countries ?? [])),
    other,
    fromGlobal,
  };
}

/** The WAF mode the host gets (as wafHostView in waf-hosts.ts). */
export function effectiveWafMode(global: WafSettings | null, host: Pick<ProxyHost, "waf">): WafEffectiveMode {
  const effective = resolveEffectiveWaf(global, host.waf);
  return effective?.enabled ? effectiveModeOfEngine(effective.mode) : "off";
}

export function protectionInputFor(host: ProxyHost, globals: Globals, accessListNames?: ReadonlyMap<number, string>): ProtectionInput {
  const rules = resolveEffectiveRateLimitRules(globals.rateLimit, host.rateLimit);
  return {
    wafMode: effectiveWafMode(globals.waf, host),
    sso: Boolean(host.ingressiForwardAuth?.enabled),
    authentik: Boolean(host.authentik?.enabled),
    forwardAuth: host.forwardAuth?.enabled ? host.forwardAuth.provider : null,
    rateLimit: { rules: rules.length, first: rules[0] ? { events: rules[0].events, window: rules[0].window } : null },
    geo: effectiveGeo(globals.geo, host),
    accessList: host.accessListId !== null ? { name: accessListNames?.get(host.accessListId) ?? null } : null,
    mtls: Boolean(host.mtls?.enabled),
  };
}

function certificateFrom(row: CertificateOverviewRow): HostCertificate {
  return {
    visible: true,
    kind: row.kind,
    name: row.kind === "acme" ? null : row.name,
    daysLeft: row.daysLeft,
    validTo: row.validTo,
    issuer: row.issuer,
    renewal: row.renewal.state,
    certificateId: row.certificateId,
    issuanceError: row.issuanceError,
  };
}

/** Each proxy host's certificate in the overview: the soonest-expiring one that names it. */
async function loadCertificates(
  access: Access,
  waitMs: number | undefined,
  now: number
): Promise<Map<number, HostCertificate> | null> {
  if (!can(access, "certificates:read")) return null;
  try {
    const overview = await buildCertificateOverview(access, { waitMs, now });
    const byHost = new Map<number, HostCertificate>();
    // Rows come soonest expiry first, so the first row naming a host wins.
    for (const row of overview.certificates) {
      const ids = [row.hostId, ...row.usedBy.filter((user) => user.kind === "proxy_host").map((user) => user.id)];
      for (const id of ids) {
        if (id !== null && !byHost.has(id)) byHost.set(id, certificateFrom(row));
      }
    }
    return byHost;
  } catch (error) {
    console.warn("[proxy-hosts] certificate overview failed:", error instanceof Error ? error.name : typeof error);
    return null;
  }
}

/** Changes waiting for approval, by host id (the oldest request of each host). */
async function loadPendingChanges(hostIds: readonly number[]): Promise<Map<number, number>> {
  const pending = new Map<number, number>();
  if (hostIds.length === 0) return pending;
  try {
    const rows = await appDb
      .select({ id: changeRequests.id, targetId: changeRequests.targetId })
      .from(changeRequests)
      .where(and(eq(changeRequests.targetType, "proxy_host"), eq(changeRequests.status, "pending"), inArray(changeRequests.targetId, [...hostIds])));
    for (const row of rows) {
      if (row.targetId !== null && (!pending.has(row.targetId) || row.id < pending.get(row.targetId)!)) pending.set(row.targetId, row.id);
    }
  } catch {
    // Before the approvals migration: nothing is pending.
  }
  return pending;
}

type Traffic = { status: AnalyticsStatus; summaries: Map<number, HostSummary>; signals: TrafficSignals | null };

async function loadTraffic(access: Access, hosts: readonly ProxyHost[], now: number): Promise<Traffic | null> {
  if (!can(access, "analytics:read")) return null;
  // Without ClickHouse there is nothing to read.
  if (!isAnalyticsEnabled()) return { status: "disabled", summaries: new Map(), signals: null };
  const range = resolveRange({ range: "24h" }, Math.floor(now / 1000));
  const domains = hosts.map((host) => ({ id: host.id, domains: host.domains.map(normalizeDomain).filter(Boolean) }));
  try {
    const [summaries, signals] = await Promise.all([
      queryHostSummaries({ range, hosts: domains, allHosts: await allProxyHostDomains() }),
      trafficSignalsFor().catch(() => null),
    ]);
    return {
      status: summaries.status,
      summaries: new Map(summaries.hosts.map((summary) => [summary.proxyHostId, summary])),
      signals: signals && signals.status === "ok" ? signals : null,
    };
  } catch {
    return { status: "unavailable", summaries: new Map(), signals: null };
  }
}

function trafficAttention(hostId: number, summary: HostSummary | undefined, signals: TrafficSignals | null): HostAttention[] {
  const items: HostAttention[] = [];
  for (const burst of signals?.errorBursts ?? []) {
    if (burst.proxyHostId !== hostId) continue;
    items.push({
      kind: "error_burst",
      tone: burst.ongoing ? "bad" : "warn",
      status: burst.status,
      count: burst.count,
      requests: burst.requests,
      start: burst.start,
      end: burst.end,
      ongoing: burst.ongoing,
      method: burst.method,
      path: burst.path,
    });
  }
  if (items.length === 0 && summary && summary.requests >= HIGH_ERROR_RATE_MIN_REQUESTS && summary.errorRate5xx >= HIGH_ERROR_RATE) {
    items.push({ kind: "error_rate", tone: "warn", rate: summary.errorRate5xx, errors: summary.errors5xx, requests: summary.requests });
  }
  for (const spike of signals?.mitigationSpikes ?? []) {
    if (spike.proxyHostId !== hostId) continue;
    items.push({ kind: "mitigation_spike", tone: "warn", count: spike.count, baseline: spike.baseline, factor: spike.factor, outcome: spike.topOutcome });
  }
  return items;
}

/** The list rows of `hosts` (already limited to what the reader may see), in the same order. */
export async function loadHostInsights(access: Access, hosts: readonly ProxyHost[], options: HostInsightOptions): Promise<HostInsights> {
  const now = options.now ?? Date.now();
  const [globals, traffic, certificates] = await Promise.all([
    loadGlobals(),
    loadTraffic(access, hosts, now),
    loadCertificates(access, options.certificateWaitMs, now),
  ]);
  const pending = await loadPendingChanges(hosts.map((host) => host.id));
  const inputs = new Map<number, ProtectionInput>();

  const rows = hosts.map((host): HostListRow => {
    const input = protectionInputFor(host, globals, options.accessListNames);
    inputs.set(host.id, input);
    const certificate: HostCertificate = certificates?.get(host.id) ?? { visible: false, automatic: host.certificateId === null };
    const summary = traffic?.summaries.get(host.id);
    const attention: HostAttention[] = [];
    if (host.enabled) {
      attention.push(...trafficAttention(host.id, summary, traffic?.signals ?? null));
      const certificateItem = certificateAttention(certificate);
      if (certificateItem) attention.push(certificateItem);
    }
    const sorted = sortAttention(attention);
    const pendingId = pending.get(host.id) ?? null;
    return {
      id: host.id,
      name: host.name,
      domains: host.domains,
      upstreams: host.upstreams,
      enabled: host.enabled,
      tags: host.tags,
      createdAt: host.createdAt,
      state: hostState(host.enabled, sorted, pendingId),
      attention: sorted,
      pendingChangeRequestId: pendingId,
      traffic: traffic
        ? {
            requests: summary?.requests ?? 0,
            errors5xx: summary?.errors5xx ?? 0,
            errorRate5xx: summary?.errorRate5xx ?? 0,
            mitigated: summary?.mitigated ?? 0,
            bytes: summary?.bytes ?? 0,
          }
        : null,
      wafMode: input.wafMode,
      protections: protectionsOf(input),
      certificate,
    };
  });
  return { rows, analyticsStatus: traffic?.status ?? null, inputs };
}
