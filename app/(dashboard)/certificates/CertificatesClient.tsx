"use client";

import Link from "next/link";
import { useState, type ReactNode } from "react";
import { Plus, SlidersHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { IssueClientCertDialog } from "@/components/ca-certificates/CaCertDialogs";
import type { CertificateOverview } from "@/src/lib/certificate-renewal";
import type { DnsProviderChoices } from "@/src/lib/dns-provider-choice";
import { ManagedCertificateSheet } from "@/components/certificates/ManagedCertificateSheet";
import type {
  CaCertificateView,
  CertificatesTab as TabId,
  ImportedCertView,
  IssuedClientCertificateView,
  ManagedCertificateView,
  MtlsRoleView,
} from "./page";
import { NO_CLIENT_CERT_FILTERS, type ClientCertFilters } from "./client-list";
import { CertificatesTab } from "./components/CertificatesTab";
import { CaTab } from "./components/CaTab";
import { ClientCertificatesTab, IssueClientCertificateMenu } from "./components/ClientCertificatesTab";
import { ImportCertDrawer } from "./components/ImportCertDrawer";
import { CaCertDrawer } from "./components/CaCertDrawer";

type Props = {
  overview: CertificateOverview;
  caCertificates: CaCertificateView[];
  clientCertificates: IssuedClientCertificateView[];
  mtlsRoles: MtlsRoleView[];
  /** The certificates Caddy obtains that the list shows, with the DNS provider each one is set to. */
  managedCertificates: ManagedCertificateView[];
  /** The DNS providers set up under Certificate settings. */
  dnsChoices: DnsProviderChoices;
  /** CA certificates, client certificates and roles: hidden under a tag scope. */
  showTrustAnchors: boolean;
  canWrite: boolean;
  /** Creating a certificate needs certificates:write without a tag scope. */
  canCreateCertificate: boolean;
  /** Shows the link to the certificate settings (ACME account, DNS providers). */
  canReadSettings: boolean;
  initialTab: TabId;
};

function TabCount({ value }: { value: number }) {
  return (
    <span className="num rounded-full bg-raise px-1.5 text-[11px] leading-[18px] font-normal text-muted-foreground">{value}</span>
  );
}

export default function CertificatesClient({
  overview,
  caCertificates,
  clientCertificates,
  mtlsRoles,
  managedCertificates,
  dnsChoices,
  showTrustAnchors,
  canWrite,
  canCreateCertificate,
  canReadSettings,
  initialTab,
}: Props) {
  const [tab, setTab] = useState<TabId>(initialTab);
  // false: closed; null: importing a new one; a certificate: editing it.
  const [importDrawer, setImportDrawer] = useState<ImportedCertView | null | false>(false);
  // The same: a new certificate Caddy obtains, or the one being edited.
  const [managedSheet, setManagedSheet] = useState<ManagedCertificateView | null | false>(false);
  const [caDrawer, setCaDrawer] = useState<CaCertificateView | null | false>(false);
  const [issueFor, setIssueFor] = useState<CaCertificateView | null>(null);
  // Kept here so a certificate authority's "Show client certificates" can set them.
  const [clientFilters, setClientFilters] = useState<ClientCertFilters>(NO_CLIENT_CERT_FILTERS);

  const primary =
    tab === "certificates" ? (
      canCreateCertificate && (
        <>
          <Button variant="outline" onClick={() => setImportDrawer(null)}>
            <Plus />
            Import certificate
          </Button>
          <Button onClick={() => setManagedSheet(null)}>
            <Plus />
            New managed certificate
          </Button>
        </>
      )
    ) : tab === "authorities" ? (
      canWrite && (
        <Button onClick={() => setCaDrawer(null)}>
          <Plus />
          Add certificate authority
        </Button>
      )
    ) : (
      canWrite && <IssueClientCertificateMenu caCertificates={caCertificates} onIssue={setIssueFor} />
    );

  const header = (tabs?: ReactNode) => (
    <PageHeader
      className="mb-0"
      breadcrumb={["Traffic", "Certificates"]}
      title="Certificates"
      actions={
        <>
          {canReadSettings && (
            <Button asChild variant="outline">
              <Link href="/certificates/settings">
                <SlidersHorizontal />
                Certificate settings
              </Link>
            </Button>
          )}
          {primary}
        </>
      }
    >
      {tabs}
    </PageHeader>
  );

  const certificatesTab = (
    <CertificatesTab
      rows={overview.certificates}
      generatedAt={overview.generatedAt}
      canWrite={canWrite}
      managedCertificates={managedCertificates}
      onEditImported={(cert) => setImportDrawer(cert)}
      onEditManaged={(cert) => setManagedSheet(cert)}
    />
  );

  return (
    <div className="flex w-full min-w-0 flex-col gap-[18px]">
      {showTrustAnchors ? (
        <Tabs value={tab} onValueChange={(value) => setTab(value as TabId)} className="flex min-w-0 flex-col gap-[18px]">
          {header(
            <TabsList aria-label="Certificate types">
              <TabsTrigger value="certificates">
                Certificates <TabCount value={overview.certificates.length} />
              </TabsTrigger>
              <TabsTrigger value="authorities">
                Certificate authorities <TabCount value={caCertificates.length} />
              </TabsTrigger>
              <TabsTrigger value="client">
                Client certificates <TabCount value={clientCertificates.length} />
              </TabsTrigger>
            </TabsList>
          )}
          <TabsContent value="certificates" className="mt-0">
            {certificatesTab}
          </TabsContent>
          <TabsContent value="authorities" className="mt-0">
            <CaTab
              caCertificates={caCertificates}
              generatedAt={overview.generatedAt}
              canWrite={canWrite}
              onAdd={() => setCaDrawer(null)}
              onEdit={(ca) => setCaDrawer(ca)}
              onIssue={setIssueFor}
              onShowClientCertificates={(ca) => {
                setClientFilters({ ...NO_CLIENT_CERT_FILTERS, caId: ca.id });
                setTab("client");
              }}
            />
          </TabsContent>
          <TabsContent value="client" className="mt-0">
            <ClientCertificatesTab
              clientCertificates={clientCertificates}
              roles={mtlsRoles}
              caCertificates={caCertificates}
              generatedAt={overview.generatedAt}
              canWrite={canWrite}
              onIssue={setIssueFor}
              filters={clientFilters}
              onFiltersChange={setClientFilters}
            />
          </TabsContent>
        </Tabs>
      ) : (
        <>
          {header()}
          {certificatesTab}
        </>
      )}

      <ImportCertDrawer open={importDrawer !== false} cert={importDrawer || null} onClose={() => setImportDrawer(false)} />
      {managedSheet !== false && (
        <ManagedCertificateSheet open cert={managedSheet} choices={dnsChoices} onClose={() => setManagedSheet(false)} />
      )}
      {showTrustAnchors && (
        <CaCertDrawer open={caDrawer !== false} cert={caDrawer || null} onClose={() => setCaDrawer(false)} />
      )}
      {issueFor && <IssueClientCertDialog open cert={issueFor} onClose={() => setIssueFor(null)} />}
    </div>
  );
}
