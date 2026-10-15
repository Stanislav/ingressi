/**
 * Every TLS certificate the product serves, as one list: the certificates
 * Caddy obtains on its own for proxy hosts without a chosen certificate
 * (ACME), imported certificates, and the older "managed" certificate entries.
 * Each row says how the certificate is obtained, when it expires, where its
 * renewal stands and which proxy hosts and L4 hosts terminate TLS with it.
 *
 * Shared by the certificates page and GET /api/v1/certificates/overview, so
 * both apply the same visibility rules: a tag scope limits the rows to the
 * certificates of in-scope proxy hosts (as the certificate list does), and
 * L4 hosts are named only to callers that may read them.
 */
import { X509Certificate } from "node:crypto";
import { appDb, toIso } from "./db";
import { certificates, proxyHosts } from "./db/schema";
import { can, scopeTagsFor, tagsInScope, type Access } from "./permissions";
import { parseStoredTags } from "./host-tags";
import { isDomainCoveredByCert } from "./cert-domain-match";
import { parseStoredCertificateProviderOptions } from "./certificate-provider-options";
import { getProviderDefinition } from "./dns-providers";
import { getAcmeSettings, getDnsProviderSettings } from "./settings";
import { listL4ProxyHosts } from "./models/l4-proxy-hosts";
import { certificateKeyType, getManagedCertificateReadings, type ManagedCertificateExpiry, type ManagedCertificateReading } from "./managed-certificates";
import {
  certificateRenewal,
  daysUntil,
  type CertificateObtainedBy,
  type CertificateOverview,
  type CertificateOverviewRow,
  type CertificateUser,
} from "./certificate-renewal";

export * from "./certificate-renewal";

export type CertificateOverviewOptions = {
  now?: number;
  /** Passed to getManagedCertificateReadings. */
  waitMs?: number;
};

type PemInfo = { validTo: string; validFrom: string; issuer: string | null; keyType: string | null; sanDomains: string[] };

export function parsePemInfo(pem: string): PemInfo | null {
  try {
    const cert = new X509Certificate(pem);
    const sanDomains =
      cert.subjectAltName
        ?.split(",")
        .map((s) => s.trim())
        .filter((s) => s.startsWith("DNS:"))
        .map((s) => s.slice(4).toLowerCase()) ?? [];
    const issuerLine = cert.issuer ?? "";
    const issuer = (issuerLine.match(/O=([^\n,]+)/)?.[1] ?? issuerLine.match(/CN=([^\n,]+)/)?.[1] ?? issuerLine).trim();
    return {
      validTo: new Date(cert.validTo).toISOString(),
      validFrom: new Date(cert.validFrom).toISOString(),
      issuer: issuer || null,
      keyType: certificateKeyType(cert),
      sanDomains,
    };
  } catch {
    return null;
  }
}

function parseDomains(raw: string): string[] {
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value)
      ? value.filter((d): d is string => typeof d === "string" && d.trim().length > 0).map((d) => d.trim().toLowerCase())
      : [];
  } catch {
    return [];
  }
}

function directoryHost(caUrl: string | undefined): string | null {
  const raw = caUrl?.trim();
  if (!raw) return null;
  try {
    return new URL(raw).host || null;
  } catch {
    return null;
  }
}

function providerDisplayName(name: string | null | undefined): string | null {
  if (!name) return null;
  return getProviderDefinition(name)?.displayName ?? name;
}

/** What Caddy showed for a row's names: the soonest-expiring certificate it serves, else "none" when it answered without one. */
type RowReading = {
  served: ManagedCertificateExpiry | null;
  /** Caddy answered a handshake for one of the names without a certificate for it. */
  none: boolean;
  /** When Caddy was last asked (the served certificate's reading, else the latest of the others). */
  checkedAt: string | null;
};

function readNames(domains: string[], readings: Map<string, ManagedCertificateReading>): RowReading {
  let served: ManagedCertificateExpiry | null = null;
  let none = false;
  let checkedAt: string | null = null;
  for (const domain of domains) {
    const reading = readings.get(domain);
    if (!reading) continue;
    if (reading.kind === "served") {
      if (!served || reading.expiry.validTo < served.validTo) served = reading.expiry;
    } else if (reading.kind === "none") {
      none = true;
    }
    const at = reading.kind === "served" ? reading.expiry.checkedAt : reading.checkedAt;
    if (!checkedAt || at > checkedAt) checkedAt = at;
  }
  return { served, none, checkedAt: served?.checkedAt ?? checkedAt };
}

function latest(...times: (string | null | undefined)[]): string | null {
  let result: string | null = null;
  for (const time of times) {
    if (time && !Number.isNaN(Date.parse(time)) && (!result || Date.parse(time) > Date.parse(result))) result = time;
  }
  return result;
}

type HostRow = {
  id: number;
  name: string;
  domains: string[];
  enabled: boolean;
  certificateId: number | null;
  tags: string[];
  updatedAt: string | null;
};

/** The certificate overview `access` may see. */
export async function buildCertificateOverview(access: Access, options: CertificateOverviewOptions = {}): Promise<CertificateOverview> {
  const now = options.now ?? Date.now();
  // A tag scope limits this view to the certificates and ACME hosts of
  // in-scope proxy hosts (see src/lib/access-scope.ts).
  const scope = scopeTagsFor(access, "certificates");
  const inScope = (tags: string[]) => tagsInScope(tags, scope);

  const [hostRows, certRows, acmeSettings, dnsProviderSettings] = await Promise.all([
    appDb
      .select({
        id: proxyHosts.id,
        name: proxyHosts.name,
        domains: proxyHosts.domains,
        enabled: proxyHosts.enabled,
        certificateId: proxyHosts.certificateId,
        tags: proxyHosts.tags,
        updatedAt: proxyHosts.updatedAt,
      })
      .from(proxyHosts)
      .orderBy(proxyHosts.name, proxyHosts.id),
    appDb.select().from(certificates).orderBy(certificates.id),
    getAcmeSettings(),
    getDnsProviderSettings(),
  ]);

  const hosts: HostRow[] = hostRows
    .map((row) => ({
      id: row.id,
      name: row.name,
      domains: parseDomains(row.domains),
      enabled: row.enabled,
      certificateId: row.certificateId ?? null,
      tags: parseStoredTags(row.tags),
      updatedAt: toIso(row.updatedAt),
    }))
    .filter((host) => !scope || inScope(host.tags));

  // L4 hosts that terminate TLS take the certificate Caddy holds for their
  // SNI names.
  const l4Hosts =
    can(access, "l4_proxy_hosts:read")
      ? (await listL4ProxyHosts(scopeTagsFor(access, "l4_proxy_hosts"))).filter(
          (host) => host.tlsTermination && host.matcherType === "tls_sni" && host.matcherValue.length > 0
        )
      : [];

  const directory = directoryHost(acmeSettings?.caUrl);
  const defaultProvider =
    dnsProviderSettings?.default && dnsProviderSettings.providers[dnsProviderSettings.default] ? dnsProviderSettings.default : null;
  const acmeObtainedBy = (providerOverride: string | null): CertificateObtainedBy => {
    const provider =
      providerOverride && dnsProviderSettings?.providers[providerOverride] ? providerOverride : defaultProvider;
    return {
      method: "acme",
      challenge: provider ? "dns-01" : "http-01",
      dnsProvider: providerDisplayName(provider),
      directory,
    };
  };

  // Certificates in view: with a scope, those an in-scope host uses.
  const usedCertIds = new Set(hosts.map((h) => h.certificateId).filter((id): id is number => id !== null));
  const visibleCerts = scope ? certRows.filter((cert) => usedCertIds.has(cert.id)) : certRows;

  const usage = new Map<number, CertificateUser[]>();
  const addUser = (certId: number, host: HostRow) => {
    const list = usage.get(certId) ?? [];
    if (!list.some((u) => u.kind === "proxy_host" && u.id === host.id)) {
      list.push({ kind: "proxy_host", id: host.id, name: host.name, domains: host.domains });
    }
    usage.set(certId, list);
  };
  for (const host of hosts) {
    if (host.certificateId !== null && visibleCerts.some((c) => c.id === host.certificateId)) addUser(host.certificateId, host);
  }

  // The names each certificate covers: an imported certificate's SANs (they
  // may include wildcards the entry does not list), else its domain list.
  const certInfo = new Map<number, { domains: string[]; pem: PemInfo | null }>();
  for (const cert of visibleCerts) {
    const listed = parseDomains(cert.domainNames);
    const pem = cert.type === "imported" && cert.certificatePem ? parsePemInfo(cert.certificatePem) : null;
    certInfo.set(cert.id, { domains: pem?.sanDomains.length ? pem.sanDomains : listed, pem });
  }

  // ACME hosts (no chosen certificate). A host whose names an existing
  // certificate covers is listed under that certificate instead.
  const acmeHosts: HostRow[] = [];
  for (const host of hosts) {
    if (host.certificateId !== null) continue;
    let coveredBy: number | null = null;
    for (const [certId, info] of certInfo) {
      if (host.domains.length > 0 && host.domains.every((d) => isDomainCoveredByCert(d, info.domains))) {
        coveredBy = certId;
        break;
      }
    }
    if (coveredBy !== null) addUser(coveredBy, host);
    else acmeHosts.push(host);
  }

  // Among ACME hosts, a host whose names a wildcard ACME host covers is not
  // listed on its own (sub.example.com under *.example.com).
  const wildcardSets = acmeHosts.filter((h) => h.domains.some((d) => d.startsWith("*."))).map((h) => h.domains);
  const listedAcmeHosts = acmeHosts.filter(
    (host) =>
      host.domains.some((d) => d.startsWith("*.")) ||
      !wildcardSets.some((set) => host.domains.length > 0 && host.domains.every((d) => isDomainCoveredByCert(d, set)))
  );

  // Read the certificates Caddy serves for enabled ACME hosts and for the
  // managed entries enabled hosts use (Caddy manages nothing for the rest).
  const managedCerts = visibleCerts.filter((cert) => cert.type !== "imported");
  const toProbe = new Set<string>();
  const enabledHostIds = new Set(hosts.filter((h) => h.enabled).map((h) => h.id));
  const inUse = (certId: number) => (usage.get(certId) ?? []).some((u) => u.kind === "proxy_host" && enabledHostIds.has(u.id));
  for (const host of listedAcmeHosts) if (host.enabled) host.domains.forEach((d) => toProbe.add(d));
  for (const cert of managedCerts) if (inUse(cert.id)) certInfo.get(cert.id)?.domains.forEach((d) => toProbe.add(d));
  const readings = toProbe.size > 0 ? await getManagedCertificateReadings([...toProbe], { waitMs: options.waitMs }) : new Map<string, ManagedCertificateReading>();

  const l4UsersFor = (domains: string[]): CertificateUser[] =>
    l4Hosts
      .filter((l4) => l4.matcherValue.some((sni) => isDomainCoveredByCert(sni.trim().toLowerCase(), domains)))
      .map((l4) => ({ kind: "l4_host" as const, id: l4.id, name: l4.name, domains: l4.matcherValue }));

  const rows: CertificateOverviewRow[] = [];
  const fallbackIssuer = directory ?? "Let's Encrypt";

  for (const host of listedAcmeHosts) {
    const reading = host.enabled ? readNames(host.domains, readings) : null;
    const cert = reading?.served ?? null;
    const coveredHosts = acmeHosts.filter(
      (other) => other.id !== host.id && !listedAcmeHosts.includes(other) && other.domains.every((d) => isDomainCoveredByCert(d, host.domains))
    );
    const row = {
      id: `acme:${host.id}`,
      kind: "acme" as const,
      certificateId: null,
      hostId: host.id,
      name: host.name,
      domains: host.domains,
      active: host.enabled,
      issuer: cert?.issuer ?? fallbackIssuer,
      issuerFromCertificate: Boolean(cert?.issuer),
      keyType: cert?.keyType ?? null,
      validFrom: cert?.validFrom ?? null,
      validTo: cert?.validTo ?? null,
      expirySource: cert ? ("caddy" as const) : null,
      checkedAt: reading?.checkedAt ?? null,
      noCertificate: reading?.none && !cert ? { savedAt: host.updatedAt } : undefined,
      obtainedBy: acmeObtainedBy(null),
      usedBy: [
        { kind: "proxy_host" as const, id: host.id, name: host.name, domains: host.domains },
        ...coveredHosts.map((h) => ({ kind: "proxy_host" as const, id: h.id, name: h.name, domains: h.domains })),
        ...l4UsersFor(host.domains),
      ],
    };
    rows.push(finishRow(row, now));
  }

  for (const cert of visibleCerts) {
    const info = certInfo.get(cert.id)!;
    const users = usage.get(cert.id) ?? [];
    const proxyUsers = users.filter((u) => u.kind === "proxy_host");
    if (cert.type === "imported") {
      rows.push(
        finishRow(
          {
            id: `certificate:${cert.id}`,
            kind: "imported",
            certificateId: cert.id,
            hostId: null,
            name: cert.name,
            domains: info.domains,
            active: true,
            issuer: info.pem?.issuer ?? null,
            issuerFromCertificate: Boolean(info.pem?.issuer),
            keyType: info.pem?.keyType ?? null,
            validFrom: info.pem?.validFrom ?? null,
            validTo: info.pem?.validTo ?? null,
            expirySource: info.pem ? "pem" : null,
            checkedAt: null,
            obtainedBy: { method: "imported" },
            usedBy: [...proxyUsers, ...l4UsersFor(info.domains)],
          },
          now
        )
      );
      continue;
    }
    const active = inUse(cert.id);
    const reading = active ? readNames(info.domains, readings) : null;
    const servedCert = reading?.served ?? null;
    const provider = parseStoredCertificateProviderOptions(cert.providerOptions)?.provider ?? null;
    rows.push(
      finishRow(
        {
          id: `certificate:${cert.id}`,
          kind: "managed",
          certificateId: cert.id,
          hostId: null,
          name: cert.name,
          domains: info.domains,
          active,
          issuer: servedCert?.issuer ?? fallbackIssuer,
          issuerFromCertificate: Boolean(servedCert?.issuer),
          keyType: servedCert?.keyType ?? null,
          validFrom: servedCert?.validFrom ?? null,
          validTo: servedCert?.validTo ?? null,
          expirySource: servedCert ? "caddy" : null,
          checkedAt: reading?.checkedAt ?? null,
          noCertificate:
            reading?.none && !servedCert
              ? { savedAt: latest(toIso(cert.updatedAt), ...proxyUsers.map((user) => hosts.find((host) => host.id === user.id)?.updatedAt)) }
              : undefined,
          obtainedBy: acmeObtainedBy(provider),
          usedBy: [...proxyUsers, ...l4UsersFor(info.domains)],
        },
        now
      )
    );
  }

  rows.sort(compareRows);
  return { generatedAt: new Date(now).toISOString(), certificates: rows };
}

function finishRow(
  { noCertificate, ...row }: Omit<CertificateOverviewRow, "daysLeft" | "renewal"> & { noCertificate?: { savedAt: string | null } },
  now: number
): CertificateOverviewRow {
  return {
    ...row,
    daysLeft: row.validTo ? daysUntil(row.validTo, now) : null,
    renewal: certificateRenewal({ ...row, noCertificate }, now),
  };
}

/** Soonest expiry first; rows without a known expiry last, by name. */
function compareRows(a: CertificateOverviewRow, b: CertificateOverviewRow): number {
  if (a.daysLeft !== null && b.daysLeft !== null && a.daysLeft !== b.daysLeft) return a.daysLeft - b.daysLeft;
  if (a.daysLeft === null && b.daysLeft !== null) return 1;
  if (a.daysLeft !== null && b.daysLeft === null) return -1;
  return (a.domains[0] ?? a.name).localeCompare(b.domains[0] ?? b.name);
}
