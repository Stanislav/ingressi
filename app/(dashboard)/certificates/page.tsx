import { X509Certificate } from 'node:crypto';
import { requirePermission } from '@/src/lib/auth';
import { can, scopeTagsFor } from '@/src/lib/permissions';
import CertificatesClient from './CertificatesClient';
import { listCaCertificates, type CaCertificate } from '@/src/lib/models/ca-certificates';
import { listIssuedClientCertificates, type IssuedClientCertificate } from '@/src/lib/models/issued-client-certificates';
import { buildRoleCertIdMap, listMtlsRoles, type MtlsRole } from '@/src/lib/models/mtls-roles';
import { listProxyHosts, type ProxyHost } from '@/src/lib/models/proxy-hosts';
import { listCertificates } from '@/src/lib/models/certificates';
import { getDnsProviderSettings } from '@/src/lib/settings';
import { getProviderDefinition } from '@/src/lib/dns-providers';
import { buildDnsProviderChoices } from '@/src/lib/dns-provider-choice';
import type { ManagedCertificateView } from '@/src/components/certificates/ManagedCertificateSheet';
import { buildCertificateOverview } from '@/src/lib/certificate-overview';
import { trustAnchorUsage, type HostRef } from './trust';

export type { CaCertificate };
export type { IssuedClientCertificate };
export type { MtlsRole };

export type CaCertificateView = CaCertificate & {
  /** Client certificates it issued here, revoked or not. */
  issued: { active: number; revoked: number };
  /** End of the CA certificate's validity (ISO 8601), null when its PEM cannot be read. */
  validTo: string | null;
  /** Proxy hosts whose mTLS trusts this CA or certificates it issued. */
  trustedBy: HostRef[];
};

/** An issued client certificate without its PEM, which the list does not need. */
export type IssuedClientCertificateView = Omit<IssuedClientCertificate, 'certificatePem'> & {
  caName: string | null;
  /** Names of the mTLS roles the certificate belongs to. */
  roles: string[];
};

export type MtlsRoleView = MtlsRole & {
  /** Ids of the active certificates in the role. */
  certificateIds: number[];
  /** Proxy hosts whose mTLS requires the role. */
  requiredBy: HostRef[];
};

/** What the import/edit drawer needs of an imported certificate. */
export type ImportedCertView = { id: number; name: string; domains: string[] };

export type CertificatesTab = 'certificates' | 'authorities' | 'client';

export type { ManagedCertificateView };

interface PageProps {
  searchParams: Promise<{ tab?: string }>;
}

function pemValidTo(pem: string): string | null {
  try {
    return new Date(new X509Certificate(pem).validTo).toISOString();
  } catch {
    return null;
  }
}

export default async function CertificatesPage({ searchParams }: PageProps) {
  const { access } = await requirePermission('certificates:read');
  // A tag scope limits the certificate list to the certificates and ACME hosts
  // of in-scope proxy hosts; CA/client certificates and mTLS roles serve every
  // host and stay hidden (see src/lib/access-scope.ts).
  const scope = scopeTagsFor(access, 'certificates');
  const hideTrustAnchors = scope !== null;
  const settingsReadable = can(access, 'settings:read');
  const { tab } = await searchParams;

  const [overview, caCerts, issuedClientCerts, roles, roleCertIds, hosts, storedCertificates, dnsSettings] = await Promise.all([
    buildCertificateOverview(access),
    hideTrustAnchors ? Promise.resolve([] as CaCertificate[]) : listCaCertificates(),
    hideTrustAnchors ? Promise.resolve([] as IssuedClientCertificate[]) : listIssuedClientCertificates(),
    hideTrustAnchors ? Promise.resolve([] as MtlsRole[]) : listMtlsRoles().catch(() => [] as MtlsRole[]),
    hideTrustAnchors
      ? Promise.resolve(new Map<number, Set<number>>())
      : buildRoleCertIdMap().catch(() => new Map<number, Set<number>>()),
    // CAs and roles serve every host, so "trusted by" looks at every host.
    hideTrustAnchors ? Promise.resolve([] as ProxyHost[]) : listProxyHosts(null),
    listCertificates(),
    getDnsProviderSettings(),
  ]);

  // What the sheet needs to change a certificate Caddy obtains: only for rows the overview shows.
  const shownCertificateIds = new Set(overview.certificates.map((row) => row.certificateId));
  const managedCertificates: ManagedCertificateView[] = storedCertificates
    .filter((cert) => cert.type === 'managed' && shownCertificateIds.has(cert.id))
    .map((cert) => ({
      id: cert.id,
      name: cert.name,
      domains: cert.domainNames,
      provider: typeof cert.providerOptions?.provider === 'string' ? cert.providerOptions.provider : null,
    }));
  const dnsChoices = buildDnsProviderChoices(dnsSettings, (name) => getProviderDefinition(name)?.displayName ?? name);

  const usage = trustAnchorUsage(hosts, issuedClientCerts, roleCertIds);
  const caNames = new Map(caCerts.map((ca) => [ca.id, ca.name]));
  const roleNamesByCert = new Map<number, string[]>();
  for (const role of roles) {
    for (const certId of roleCertIds.get(role.id) ?? []) {
      roleNamesByCert.set(certId, [...(roleNamesByCert.get(certId) ?? []), role.name]);
    }
  }

  const issuedByCa = new Map<number, { active: number; revoked: number }>();
  for (const cert of issuedClientCerts) {
    const counts = issuedByCa.get(cert.caCertificateId) ?? { active: 0, revoked: 0 };
    if (cert.revokedAt) counts.revoked++;
    else counts.active++;
    issuedByCa.set(cert.caCertificateId, counts);
  }

  const caCertificates: CaCertificateView[] = caCerts.map((ca) => ({
    ...ca,
    issued: issuedByCa.get(ca.id) ?? { active: 0, revoked: 0 },
    validTo: pemValidTo(ca.certificatePem),
    trustedBy: usage.caTrustedBy.get(ca.id) ?? [],
  }));
  const clientCertificates: IssuedClientCertificateView[] = issuedClientCerts.map((cert) => ({
    id: cert.id,
    caCertificateId: cert.caCertificateId,
    commonName: cert.commonName,
    serialNumber: cert.serialNumber,
    fingerprintSha256: cert.fingerprintSha256,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    revokedAt: cert.revokedAt,
    createdAt: cert.createdAt,
    updatedAt: cert.updatedAt,
    caName: caNames.get(cert.caCertificateId) ?? null,
    roles: roleNamesByCert.get(cert.id) ?? [],
  }));
  const mtlsRoles: MtlsRoleView[] = roles.map((role) => ({
    ...role,
    certificateIds: [...(roleCertIds.get(role.id) ?? [])],
    requiredBy: usage.roleRequiredBy.get(role.id) ?? [],
  }));

  const canWrite = can(access, 'certificates:write');

  return (
    <CertificatesClient
      overview={overview}
      caCertificates={caCertificates}
      clientCertificates={clientCertificates}
      mtlsRoles={mtlsRoles}
      managedCertificates={managedCertificates}
      dnsChoices={dnsChoices}
      showTrustAnchors={!hideTrustAnchors}
      canWrite={canWrite}
      canCreateCertificate={canWrite && scope === null}
      canReadSettings={settingsReadable}
      initialTab={!hideTrustAnchors && (tab === 'authorities' || tab === 'client') ? tab : 'certificates'}
    />
  );
}
