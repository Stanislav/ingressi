/**
 * The rows of the certificate overview and where a certificate's renewal
 * stands: types and pure functions, with no server imports, so client
 * components can use them (src/lib/certificate-overview.ts builds the rows).
 */

export const DAY_MS = 86_400_000;
/**
 * How long Caddy gets to obtain the first certificate of a host or entry
 * saved just now (DNS challenges wait for propagation) before the missing
 * certificate counts as a failure. The attention list uses the same limit.
 */
export const FIRST_CERTIFICATE_GRACE_MS = 15 * 60 * 1000;
/** The renewal band the page draws: Caddy renews a 90-day certificate with 30 days left. */
export const RENEWAL_WINDOW_DAYS = 30;
/** Under this many days left an expiry is urgent. */
export const URGENT_DAYS = 7;

export type CertificateKind = "acme" | "imported" | "managed";

export type CertificateUser = {
  kind: "proxy_host" | "l4_host";
  id: number;
  name: string;
  /** Proxy host: its domains. L4 host: the SNI names it matches. */
  domains: string[];
};

export type CertificateObtainedBy =
  | {
      method: "acme";
      challenge: "http-01" | "dns-01";
      /** Display name of the DNS provider for DNS-01. */
      dnsProvider: string | null;
      /** Host of a custom ACME directory (an internal CA); null for Let's Encrypt. */
      directory: string | null;
    }
  | { method: "imported" };

export type RenewalState =
  /** Caddy renews it on its own; renewal has not started. */
  | "scheduled"
  /** In its renewal window; Caddy is renewing it. */
  | "due"
  /** Past the middle of its renewal window and still not renewed. */
  | "overdue"
  | "expired"
  /** Imported: replaced by hand, not due yet. */
  | "manual"
  /** Imported and under 30 days left. */
  | "replace_soon"
  /** Caddy has no certificate yet and the host or entry was saved a moment ago: the first one is being obtained. */
  | "pending"
  /** Caddy still has no certificate a while after the host or entry was saved: obtaining the first one is failing. */
  | "missing"
  /** The expiry could not be read (Caddy was not reachable, or the check has not finished). */
  | "unknown"
  /** The host is disabled, so Caddy manages no certificate for it. */
  | "inactive";

export type CertificateRenewal = {
  state: RenewalState;
  /** When Caddy starts renewing it (ISO 8601): a third of its lifetime before expiry. */
  renewFrom: string | null;
};

export type CertificateOverviewRow = {
  /** "acme:<proxy host id>" or "certificate:<certificate id>". */
  id: string;
  kind: CertificateKind;
  /** The certificate's id (imported and managed rows). */
  certificateId: number | null;
  /** The proxy host the certificate is obtained for (ACME rows). */
  hostId: number | null;
  /** The proxy host's name (ACME) or the certificate's name. */
  name: string;
  domains: string[];
  /**
   * ACME rows: the host is enabled. Managed entries: an enabled host uses it.
   * Imported certificates: always true. Caddy manages nothing for inactive rows.
   */
  active: boolean;
  issuer: string | null;
  /** True when the issuer was read from the certificate itself, false when it is the configured CA. */
  issuerFromCertificate: boolean;
  keyType: string | null;
  validFrom: string | null;
  validTo: string | null;
  /** Where the dates come from: the stored PEM, or the certificate Caddy serves. */
  expirySource: "pem" | "caddy" | null;
  /** Whole days left (negative once expired); null when the expiry is not known. */
  daysLeft: number | null;
  /** When Caddy was last asked for the certificate (ISO 8601); null before the first check. */
  checkedAt: string | null;
  obtainedBy: CertificateObtainedBy;
  renewal: CertificateRenewal;
  usedBy: CertificateUser[];
};

export type CertificateOverview = {
  generatedAt: string;
  certificates: CertificateOverviewRow[];
};

/** Whole days from `now` to `validTo`; negative once expired. */
export function daysUntil(validTo: string, now: number): number {
  return Math.floor((new Date(validTo).getTime() - now) / DAY_MS);
}

/**
 * Where a certificate's renewal stands. Caddy renews ACME certificates when a
 * third of their lifetime is left (30 days of 90); imported ones are replaced
 * by hand.
 */
export function certificateRenewal(
  input: {
    kind: CertificateKind;
    active: boolean;
    validFrom: string | null;
    validTo: string | null;
    /** Caddy answered a TLS handshake without a certificate for the name; `savedAt` is when the host or entry last changed. */
    noCertificate?: { savedAt: string | null };
  },
  now: number
): CertificateRenewal {
  if (!input.active) return { state: "inactive", renewFrom: null };
  if (!input.validTo) {
    if (!input.noCertificate) return { state: "unknown", renewFrom: null };
    const savedAt = input.noCertificate.savedAt ? Date.parse(input.noCertificate.savedAt) : Number.NaN;
    return { state: !Number.isNaN(savedAt) && now - savedAt < FIRST_CERTIFICATE_GRACE_MS ? "pending" : "missing", renewFrom: null };
  }
  const validTo = new Date(input.validTo).getTime();
  if (Number.isNaN(validTo)) return { state: "unknown", renewFrom: null };
  if (validTo <= now) return { state: "expired", renewFrom: null };
  if (input.kind === "imported") {
    return { state: validTo - now <= RENEWAL_WINDOW_DAYS * DAY_MS ? "replace_soon" : "manual", renewFrom: null };
  }
  const validFrom = input.validFrom ? new Date(input.validFrom).getTime() : Number.NaN;
  const lifetime = Number.isNaN(validFrom) || validFrom >= validTo ? 90 * DAY_MS : validTo - validFrom;
  const window = lifetime / 3;
  const renewFrom = validTo - window;
  const state: RenewalState = now < renewFrom ? "scheduled" : validTo - now <= window / 2 ? "overdue" : "due";
  return { state, renewFrom: new Date(renewFrom).toISOString() };
}

/** Rows that need attention: in their renewal window, overdue, expired, to be replaced soon or never issued. */
export function needsAttention(row: Pick<CertificateOverviewRow, "renewal">): boolean {
  return ["due", "overdue", "expired", "replace_soon", "missing"].includes(row.renewal.state);
}

/** Rows whose renewal is in order. */
export function isHealthy(row: Pick<CertificateOverviewRow, "renewal">): boolean {
  return row.renewal.state === "scheduled" || row.renewal.state === "manual";
}
