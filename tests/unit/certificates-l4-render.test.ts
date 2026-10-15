/**
 * Server-side render of the redesigned certificates and L4 hosts pages:
 * the three certificate tabs, the expiry timeline, the certificate table's
 * columns and states, and the L4 hosts list with its filters. No invented
 * traffic metrics on the L4 page.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/l4-proxy-hosts',
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/app/(dashboard)/certificates/actions', () => ({
  createCertificateAction: vi.fn(),
  updateCertificateAction: vi.fn(),
  deleteCertificateAction: vi.fn(),
  saveManagedCertificateAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/certificates/ca-actions', () => ({
  createCaCertificateAction: vi.fn(),
  updateCaCertificateAction: vi.fn(),
  deleteCaCertificateAction: vi.fn(),
  generateCaCertificateAction: vi.fn(),
  issueClientCertificateAction: vi.fn(),
  revokeIssuedClientCertificateAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/l4-proxy-hosts/actions', () => ({
  createL4ProxyHostAction: vi.fn(),
  updateL4ProxyHostAction: vi.fn(),
  deleteL4ProxyHostAction: vi.fn(),
  toggleL4ProxyHostAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/l4-proxy-hosts/bulk-actions', () => ({ bulkL4ProxyHostsAction: vi.fn() }));

import CertificatesClient from '@/app/(dashboard)/certificates/CertificatesClient';
import { NO_DNS_PROVIDERS } from '@/src/lib/dns-provider-choice';
import type { CaCertificateView, IssuedClientCertificateView, MtlsRoleView } from '@/app/(dashboard)/certificates/page';
import L4ProxyHostsClient from '@/app/(dashboard)/l4-proxy-hosts/L4ProxyHostsClient';
import type { CertificateOverviewRow } from '@/src/lib/certificate-renewal';
import type { L4ProxyHost } from '@/src/lib/models/l4-proxy-hosts';

const NOW = '2026-10-03T12:00:00.000Z';
const day = (offset: number) => new Date(Date.parse(NOW) + offset * 86_400_000).toISOString();

const rows: CertificateOverviewRow[] = [
  {
    id: 'acme:1',
    kind: 'acme',
    certificateId: null,
    hostId: 1,
    name: 'Auth',
    domains: ['auth.example.com'],
    active: true,
    issuer: "Let's Encrypt",
    issuerFromCertificate: true,
    keyType: 'ECDSA P-256',
    validFrom: day(-59),
    validTo: day(31),
    expirySource: 'caddy',
    checkedAt: null,
    issuanceError: null,
    daysLeft: 31,
    obtainedBy: { method: 'acme', challenge: 'http-01', dnsProvider: null, directory: null },
    renewal: { state: 'scheduled', renewFrom: day(1) },
    usedBy: [
      { kind: 'proxy_host', id: 1, name: 'Auth', domains: ['auth.example.com'] },
      { kind: 'l4_host', id: 9, name: 'DNS over TLS', domains: ['auth.example.com'] },
    ],
  },
  {
    id: 'certificate:4',
    kind: 'imported',
    certificateId: 4,
    hostId: null,
    name: 'Files wildcard',
    domains: ['files.example.com', '*.files.example.com'],
    active: true,
    issuer: 'Example CA',
    issuerFromCertificate: true,
    keyType: 'RSA 2048',
    validFrom: day(-300),
    validTo: day(20),
    expirySource: 'pem',
    checkedAt: null,
    issuanceError: null,
    daysLeft: 20,
    obtainedBy: { method: 'imported' },
    renewal: { state: 'replace_soon', renewFrom: null },
    usedBy: [],
  },
  {
    id: 'acme:2',
    kind: 'acme',
    certificateId: null,
    hostId: 2,
    name: 'Grafana',
    domains: ['grafana.example.com'],
    active: true,
    issuer: "Let's Encrypt",
    issuerFromCertificate: false,
    keyType: null,
    validFrom: null,
    validTo: null,
    expirySource: null,
    checkedAt: null,
    issuanceError: null,
    daysLeft: null,
    obtainedBy: { method: 'acme', challenge: 'dns-01', dnsProvider: 'Cloudflare', directory: null },
    renewal: { state: 'unknown', renewFrom: null },
    usedBy: [{ kind: 'proxy_host', id: 2, name: 'Grafana', domains: ['grafana.example.com'] }],
  },
];

const ca: CaCertificateView = {
  id: 1,
  name: 'Staff client CA',
  certificatePem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----',
  hasPrivateKey: true,
  createdAt: '2026-03-02T00:00:00.000Z',
  updatedAt: '2026-03-02T00:00:00.000Z',
  issued: { active: 1, revoked: 0 },
  validTo: '2036-03-02T00:00:00.000Z',
  trustedBy: [{ id: 3, name: 'Registry', domain: 'registry.example.com' }],
};
const clientCert: IssuedClientCertificateView = {
  id: 7,
  caCertificateId: 1,
  commonName: 'ci-runner',
  serialNumber: 'AB',
  fingerprintSha256: 'aa',
  validFrom: '2026-03-12T00:00:00.000Z',
  validTo: '2027-03-12T00:00:00.000Z',
  revokedAt: null,
  createdAt: '2026-03-12T00:00:00.000Z',
  updatedAt: '2026-03-12T00:00:00.000Z',
  caName: 'Staff client CA',
  roles: ['automation'],
};
const role: MtlsRoleView = {
  id: 5,
  name: 'automation',
  description: 'CI runners',
  certificateCount: 1,
  createdAt: '2026-03-12T00:00:00.000Z',
  updatedAt: '2026-03-12T00:00:00.000Z',
  certificateIds: [7],
  requiredBy: [{ id: 3, name: 'Registry', domain: 'registry.example.com' }],
};

function renderCertificates(initialTab: 'certificates' | 'authorities' | 'client', showTrustAnchors = true) {
  return renderToStaticMarkup(
    createElement(CertificatesClient, {
      overview: { generatedAt: NOW, certificates: rows },
      caCertificates: [ca],
      clientCertificates: [clientCert],
      mtlsRoles: [role],
      managedCertificates: [],
      dnsChoices: NO_DNS_PROVIDERS,
      showTrustAnchors,
      canWrite: true,
      canCreateCertificate: true,
      canReadSettings: true,
      initialTab,
    })
  );
}

describe('certificates page', () => {
  it('renders the three tabs, the timeline and the certificate table', () => {
    const html = renderCertificates('certificates');
    expect(html).toContain('Certificates</h1>');
    for (const tab of ['Certificate authorities', 'Client certificates']) expect(html).toContain(tab);
    expect(html).toContain('Expiry, next 90 days');
    expect(html).toContain('aria-label="auth.example.com: 31 days left');
    expect(html).toContain('href="/certificates/settings"');
    expect(html).toContain('Certificate settings');
    expect(html).toContain('Import certificate');
    for (const column of ['Domains', 'Issuer', 'Obtained by', 'Expires', 'Renewal', 'Used by']) expect(html).toContain(`>${column}</th>`);
    // ACME: served certificate, renewal date; imported: replace soon; unread: not read yet.
    expect(html).toContain('From 4 Oct');
    expect(html).toContain('Replace soon');
    expect(html).toContain('Not read yet');
    expect(html).toContain('Cloudflare');
    // Used by: a proxy host and an L4 host.
    expect(html).toContain('1 proxy host, and DNS over TLS (L4)');
    // No footnotes about the ACME account or where the expiry comes from.
    expect(html).not.toContain('ACME account');
    expect(html).not.toContain('at most an hour');
    expect(html).not.toContain('not shown');
    // One page: no pager.
    expect(html).not.toContain('aria-label="Pages of certificates"');
  });

  it('says a certificate was never issued, apart from one not read yet, and offers a managed certificate with a DNS provider', () => {
    const grafana = rows[2];
    const never: CertificateOverviewRow = {
      ...grafana,
      checkedAt: '2026-10-03T11:05:00.000Z',
      renewal: { state: 'missing', renewFrom: null },
      issuanceError: { at: '2026-10-03T11:04:00.000Z', message: 'presenting for challenge: expected 1 zone, got 0' },
    };
    const fresh: CertificateOverviewRow = { ...grafana, id: 'acme:9', hostId: 9, domains: ['fresh.example.com'], renewal: { state: 'pending', renewFrom: null } };
    const html = renderToStaticMarkup(
      createElement(CertificatesClient, {
        overview: { generatedAt: NOW, certificates: [never, fresh] },
        caCertificates: [],
        clientCertificates: [],
        mtlsRoles: [],
        managedCertificates: [],
        dnsChoices: { providers: [{ name: 'godaddy', label: 'GoDaddy' }], defaultProvider: null },
        showTrustAnchors: false,
        canWrite: true,
        canCreateCertificate: true,
        canReadSettings: true,
        initialTab: 'certificates',
      })
    );
    expect(html).toContain('Not issued');
    expect(html).toContain('Caddy has none; checked 3 Oct 11:05 UTC');
    expect(html).toContain('Obtaining');
    // Caddy's last error, under the status.
    expect(html).toContain('presenting for challenge: expected 1 zone, got 0');
    expect(html).toContain('title="Caddy&#x27;s error of 3 Oct 11:04 UTC"');
    expect(html).toContain('No certificate');
    expect(html).not.toContain('Not read yet');
    // The failing one counts under "Needs attention", which was "Due for renewal".
    expect(html).toMatch(/Needs attention <span class="num text-warn">1<\/span>/);
    expect(html).not.toContain('Due for renewal');
    expect(html).toContain('New managed certificate');
    expect(html).toContain('Import certificate');
  });

  it('leaves certificates expiring after 90 days off the timeline', () => {
    const far: CertificateOverviewRow = { ...rows[1], id: 'certificate:5', certificateId: 5, domains: ['far.example.com'], validTo: day(200), daysLeft: 200, renewal: { state: 'manual', renewFrom: null } };
    const html = renderToStaticMarkup(
      createElement(CertificatesClient, {
        overview: { generatedAt: NOW, certificates: [far] },
        caCertificates: [],
        clientCertificates: [],
        mtlsRoles: [],
        managedCertificates: [],
        dnsChoices: NO_DNS_PROVIDERS,
        showTrustAnchors: false,
        canWrite: true,
        canCreateCertificate: true,
        canReadSettings: true,
        initialTab: 'certificates',
      })
    );
    expect(html).not.toContain('far.example.com: 200 days left');
    expect(html).toContain('Nothing expires in the next 90 days.');
    expect(html).toContain('far.example.com');
  });

  it('renders the certificate authorities tab', () => {
    const html = renderCertificates('authorities');
    expect(html).toContain('>Certificate authorities</h2>');
    expect(html).toContain('Stored, encrypted');
    expect(html).toContain('2 Mar 2036');
    expect(html).toContain('More actions for Staff client CA');
    expect(html).toContain('Add certificate authority');
    // The issued count opens the client certificates of the CA.
    expect(html).toMatch(/<button[^>]*><span class="num">1<\/span> active<\/button>/);
  });

  it('renders roles and client certificates together', () => {
    const html = renderCertificates('client');
    expect(html).toContain('CI runners. <span class="num">1</span> certificate');
    expect(html).toContain('required by registry.example.com');
    expect(html).toContain('ci-runner');
    expect(html).toContain('aria-label="Revoke ci-runner"');
    expect(html).toContain('aria-label="Select ci-runner"');
    expect(html).toContain('Issue client certificate');
    // Search, status filter and sortable columns; a table on wide screens, cards on phones.
    expect(html).toContain('placeholder="Common name, serial, role or CA"');
    expect(html).toContain('aria-label="Status"');
    expect(html).toContain('aria-sort="ascending"');
    expect(html).toContain('<ul aria-label="Client certificates"');
    expect(html).not.toContain('aria-label="Pages of client certificates"');
  });

  it('pages a long list of client certificates', () => {
    const many = Array.from({ length: 60 }, (_, i) => ({
      ...clientCert,
      id: 100 + i,
      commonName: `device-${String(i).padStart(2, '0')}`,
      validTo: day(400 + i),
    }));
    const html = renderToStaticMarkup(
      createElement(CertificatesClient, {
        overview: { generatedAt: NOW, certificates: rows },
        caCertificates: [{ ...ca, issued: { active: 60, revoked: 0 } }],
        clientCertificates: many,
        mtlsRoles: [],
        managedCertificates: [],
        dnsChoices: NO_DNS_PROVIDERS,
        showTrustAnchors: true,
        canWrite: true,
        canCreateCertificate: true,
        canReadSettings: false,
        initialTab: 'client',
      })
    );
    expect(html).toContain('aria-label="Pages of client certificates"');
    expect(html).toMatch(/<span class="num">1<\/span>–<span class="num">25<\/span> of <span class="num">60<\/span> client certificates/);
    expect(html).toContain('device-24');
    expect(html).not.toContain('device-25');
    expect(html).not.toContain('/certificates/settings');
  });

  it('shows only the certificate list without trust anchors', () => {
    const html = renderCertificates('certificates', false);
    expect(html).not.toContain('role="tablist"');
    expect(html).not.toContain('Certificate authorities');
  });
});

describe('L4 hosts page', () => {
  const base: L4ProxyHost = {
    id: 1,
    name: 'DNS over TLS',
    protocol: 'tcp',
    listenAddress: ':853',
    upstreams: ['adguard:53'],
    matcherType: 'tls_sni',
    matcherValue: ['dns.example.com'],
    tlsTermination: true,
    proxyProtocolVersion: null,
    proxyProtocolReceive: false,
    enabled: true,
    meta: null,
    loadBalancer: null,
    dnsResolver: null,
    upstreamDnsResolution: null,
    geoblock: null,
    geoblockMode: 'merge',
    tags: ['network'],
    createdAt: NOW,
    updatedAt: NOW,
  };
  const hosts: L4ProxyHost[] = [
    base,
    { ...base, id: 2, name: 'WireGuard', protocol: 'udp', listenAddress: ':51820', upstreams: ['wireguard:51820'], matcherType: 'none', matcherValue: [], tlsTermination: false, tags: [] },
    { ...base, id: 3, name: 'Mail', listenAddress: ':993', upstreams: ['dovecot:10993'], matcherType: 'none', matcherValue: [], tlsTermination: false, proxyProtocolVersion: 'v2', enabled: false, tags: [] },
  ];

  function render(list: L4ProxyHost[], totalHosts = list.length, canWrite = true) {
    return renderToStaticMarkup(
      createElement(L4ProxyHostsClient, {
        hosts: list,
        totalHosts,
        pagination: { total: list.length, page: 1, perPage: 25 },
        query: { search: '', protocol: 'all', status: 'all', sortBy: 'createdAt', sortDir: 'desc', page: 1 },
        protocolCounts: { all: 3, tcp: 2, udp: 1 },
        statusCounts: { all: 3, enabled: 2, disabled: 1 },
        showTags: true,
        canWrite,
      })
    );
  }

  it('renders the filters and one compact row per host', () => {
    const html = render(hosts);
    expect(html).toContain('L4 hosts');
    expect(html).toContain('New L4 host');
    expect(html).toContain('aria-label="Protocol"');
    expect(html).toContain('aria-label="Status"');
    expect(html).toContain('placeholder="Name, port, upstream or server name"');
    for (const column of ['Name', 'Listen', 'Upstream', 'Tags', 'Status']) expect(html).toMatch(new RegExp(`<th[^>]*>(<button[^>]*>)?${column}`));
    // The row: the server name it routes by, the listen address, the first upstream, the status.
    expect(html).toContain('dns.example.com');
    expect(html).toContain(':51820');
    expect(html).toContain('dovecot:10993');
    expect(html).toContain('Disabled');
    expect(html).toContain('network');
    expect(html).toContain('More actions for WireGuard');
    expect(html).toContain('aria-label="Select every host on this page"');
    // Settings live in the detail sheet, opened from the host's name: not in the rows.
    expect(html).not.toContain('On, certificate for dns.example.com');
    expect(html).not.toMatch(/Open now|Transferred|Open connections/);
    // Everything fits on one page: no pager.
    expect(html).not.toContain('Pages of L4 hosts');
  });

  it('has no selection or switches for a reader', () => {
    const html = render(hosts, 3, false);
    expect(html).not.toContain('Select every host on this page');
    expect(html).not.toContain('role="switch"');
    expect(html).not.toContain('New L4 host');
  });

  it('shows an empty state with one action when there are no L4 hosts', () => {
    const html = render([], 0);
    expect(html).toContain('No L4 hosts yet');
    expect(html).not.toContain('<table');
  });
});
