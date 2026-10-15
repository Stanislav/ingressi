/**
 * Labels of the certificates page: dates, time left, renewal states, how a
 * certificate is obtained and who uses it. Pure functions in UTC, so the
 * server render and the browser agree.
 */
import type { StatusTone } from "@/components/ui/StatusDot";
import type { ExpiryTone } from "@/components/ui/ExpiryTimeline";
import type {
  CertificateObtainedBy,
  CertificateOverviewRow,
  CertificateUser,
} from "@/src/lib/certificate-renewal";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY_MS = 86_400_000;

/** "3 Nov 2026". */
export function formatDate(value: string | number): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "–";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** "4 Oct". */
export function formatShortDate(value: string | number): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "–";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "31 days", "1 day", "today", "expired 3 days ago". */
export function daysLeftText(daysLeft: number): string {
  if (daysLeft < 0) return `expired ${plural(-daysLeft, "day", "days")} ago`;
  if (daysLeft === 0) return "today";
  return plural(daysLeft, "day", "days");
}

/** Time left in the largest sensible unit: "43 days", "11 months", "9 years". */
export function timeLeftText(validTo: string, now: number): string {
  const days = Math.floor((new Date(validTo).getTime() - now) / DAY_MS);
  if (days < 0) return `expired ${plural(-days, "day", "days")} ago`;
  if (days < 90) return plural(days, "day", "days");
  if (days < 730) return plural(Math.floor(days / 30.44), "month", "months");
  return plural(Math.floor(days / 365.25), "year", "years");
}

/** "3 Nov 12:05 UTC" for a check time. */
export function formatCheckedAt(value: string | number): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "–";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

export type RenewalView = { tone: StatusTone; label: string; detail: string };

/** The renewal column: a status with one line of detail ("" when the status says it all). */
export function renewalView(row: CertificateOverviewRow, now: number): RenewalView {
  const { state, renewFrom } = row.renewal;
  const imported = row.kind === "imported";
  switch (state) {
    case "scheduled":
      return { tone: "ok", label: "Automatic", detail: renewFrom ? `From ${formatShortDate(renewFrom)}` : "Caddy renews it" };
    case "due": {
      const started = renewFrom ? new Date(renewFrom).getTime() <= now : true;
      return {
        tone: "warn",
        label: "Due now",
        detail: started ? "Caddy is renewing it" : `Caddy renews it from ${formatShortDate(renewFrom!)}`,
      };
    }
    case "overdue":
      return { tone: "bad", label: "Overdue", detail: "Not renewed yet; check Caddy's log" };
    case "expired":
      return { tone: "bad", label: "Expired", detail: imported ? "Import a renewed certificate" : "Caddy could not renew it" };
    case "manual":
      return { tone: "ok", label: "Manual", detail: "Replaced by hand" };
    case "replace_soon":
      return { tone: "warn", label: "Replace soon", detail: "Import a renewed certificate" };
    case "inactive":
      return {
        tone: "off",
        label: "Not managed",
        detail: row.kind === "acme" ? "The host is disabled" : "No enabled host uses it",
      };
    case "pending":
      return { tone: "off", label: "Obtaining", detail: "Caddy is getting the first certificate" };
    case "missing":
      return {
        tone: "bad",
        label: "Not issued",
        detail: row.checkedAt ? `Caddy has none; checked ${formatCheckedAt(row.checkedAt)}` : "Caddy has none; check its log",
      };
    case "unknown":
    default:
      return imported
        ? { tone: "off", label: "Unknown", detail: "The certificate could not be read" }
        : { tone: "off", label: "Automatic", detail: "" };
  }
}

/** What the expiry column says when there is no expiry: no certificate at all, or one not read yet. */
export function noExpiryText(row: CertificateOverviewRow, sentence = false): string {
  if (row.renewal.state === "missing" || row.renewal.state === "pending") return sentence ? "No certificate yet" : "No certificate";
  return sentence ? "Expiry not read yet" : "Not read yet";
}

/** The timeline marker's colour for a row. */
export function expiryToneFor(row: CertificateOverviewRow): ExpiryTone {
  switch (row.renewal.state) {
    case "overdue":
    case "expired":
    case "missing":
      return "bad";
    case "due":
    case "replace_soon":
      return "warn";
    default:
      return row.daysLeft !== null && row.daysLeft < 7 ? "bad" : "ok";
  }
}

/** The "Obtained by" column: the method and, for DNS-01, the DNS provider (detail "" when there is none). */
export function obtainedView(obtainedBy: CertificateObtainedBy): { label: string; detail: string } {
  if (obtainedBy.method === "imported") return { label: "Imported", detail: "" };
  if (obtainedBy.challenge === "dns-01") return { label: "DNS-01", detail: obtainedBy.dnsProvider ?? "" };
  return { label: "HTTP-01", detail: "" };
}

/** One line for the timeline tooltip: "DNS-01 with Cloudflare · renews from 28 Nov". */
export function timelineDetail(row: CertificateOverviewRow): string {
  const obtained = row.obtainedBy.method === "imported"
    ? "Imported"
    : row.obtainedBy.challenge === "dns-01"
      ? `DNS-01${row.obtainedBy.dnsProvider ? ` with ${row.obtainedBy.dnsProvider}` : ""}`
      : "HTTP-01";
  const when = row.renewal.renewFrom
    ? `renews from ${formatShortDate(row.renewal.renewFrom)}`
    : row.kind === "imported"
      ? "replaced by hand"
      : null;
  const expires = row.validTo ? `expires ${formatDate(row.validTo)}` : null;
  return [expires, obtained, when].filter(Boolean).join(" · ");
}

/** "1 host", "3 hosts". */
export function hostCountText(count: number): string {
  return plural(count, "host", "hosts");
}

/** The second line of the "Used by" column: the one host's name, or what kinds of hosts. */
export function usedBySummary(users: readonly CertificateUser[]): string {
  if (users.length === 1) return users[0].kind === "l4_host" ? `${users[0].name} (L4)` : users[0].name;
  const proxies = users.filter((u) => u.kind === "proxy_host").length;
  const l4 = users.filter((u) => u.kind === "l4_host");
  const parts: string[] = [];
  if (proxies > 0) parts.push(plural(proxies, "proxy host", "proxy hosts"));
  if (l4.length === 1) parts.push(`${l4[0].name} (L4)`);
  else if (l4.length > 1) parts.push(plural(l4.length, "L4 host", "L4 hosts"));
  return parts.join(", and ");
}

/** Where a host of the "Used by" column opens. */
export function userHref(user: CertificateUser): string {
  if (user.kind === "l4_host") return `/l4-proxy-hosts?search=${encodeURIComponent(user.name)}`;
  return `/proxy-hosts?search=${encodeURIComponent(user.domains[0] ?? user.name)}`;
}

/** Text a search matches against: domains, name, issuer and the hosts using it. */
export function rowSearchText(row: CertificateOverviewRow): string {
  return [
    ...row.domains,
    row.name,
    row.issuer ?? "",
    ...row.usedBy.flatMap((u) => [u.name, ...u.domains]),
  ]
    .join(" ")
    .toLowerCase();
}
