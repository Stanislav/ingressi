// SPDX-License-Identifier: Elastic-2.0
/**
 * Pure helpers of the Alerts page: severity labels, the usual severity of each
 * rule type, durations, where a subject can be looked at more closely, channel
 * destinations in words and alert episodes (a firing event with the resolve
 * event that ended it). Safe on the server and the client.
 */
import {
  CHANNEL_TYPE_LABELS,
  RULE_TYPE_LABELS,
  type AlertChannelView,
  type AlertEventView,
  type AlertRuleView,
  type EmailChannelView,
  type NtfyChannelView,
  type TelegramChannelView,
  type PagerDutyChannelView,
  type RuleType,
  type Severity,
  type WebhookChannelView,
  type WebhookUrlChannelView,
} from "@/ee/alerting/types";

export const SEVERITY_LABELS: Record<Severity, string> = { critical: "Critical", warning: "Warning", info: "Info" };

/**
 * The severity a rule type fires with (ee/alerting/evaluators.ts), and when
 * it escalates. Shown on the rules table; the event itself carries the real one.
 */
export const RULE_SEVERITY: Record<RuleType, { severity: Severity; note: string | null }> = {
  cert_expiring: { severity: "warning", note: "critical under 3 days" },
  upstream_down: { severity: "critical", note: null },
  waf_spike: { severity: "warning", note: null },
  error_rate: { severity: "critical", note: null },
  instance_sync_failed: { severity: "warning", note: null },
  caddy_apply_failed: { severity: "critical", note: null },
  backup_failed: { severity: "warning", note: "critical from 3 failures" },
  approval_pending: { severity: "info", note: null },
  access_review_started: { severity: "info", note: null },
  access_review_overdue: { severity: "warning", note: null },
  fleet_drift: { severity: "warning", note: null },
  fleet_rollout_failed: { severity: "critical", note: null },
};

/** "under 1 min", "2 min", "1 h 20 min", "4 days". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 60_000) return "under 1 min";
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    const rest = minutes % 60;
    return rest > 0 && hours < 10 ? `${hours} h ${rest} min` : `${hours} h`;
  }
  const days = Math.floor(hours / 24);
  return `${days} days`;
}

/** A cooldown in words: "no cooldown", "15 min", "24 h", "7 days". */
export function formatMinutes(minutes: number): string {
  if (minutes <= 0) return "no cooldown";
  if (minutes < 60 || minutes % 60 !== 0) return `${minutes} min`;
  const hours = minutes / 60;
  if (hours < 24 || hours % 24 !== 0) return `${hours} h`;
  const days = hours / 24;
  return days === 1 ? "24 h" : `${days} days`;
}

/** The parameters of a rule in words, e.g. "within 14 days" or "5xx above 1% in 5 min". */
export function paramsSummary(rule: AlertRuleView): string {
  const params = rule.params as Record<string, unknown>;
  switch (rule.type) {
    case "cert_expiring":
      return `Within ${params.days ?? 14} days${params.includeClientCertificates === false ? ", without client certificates" : ""}`;
    case "upstream_down":
      return `${params.minFails ?? 1}+ recent failures`;
    case "waf_spike":
      return `${params.threshold ?? 100}+ blocked in ${params.windowMinutes ?? 15} min`;
    case "error_rate":
      return `5xx above ${params.thresholdPercent ?? 5}% in ${params.windowMinutes ?? 5} min, at least ${params.minRequests ?? 20} requests`;
    case "backup_failed":
      return `${params.minFailures ?? 1}+ failures in a row`;
    default:
      return "";
  }
}

/** The second line of a rule's condition cell. */
export function conditionLine(rule: AlertRuleView): string {
  const parts = [RULE_TYPE_LABELS[rule.type]];
  const params = paramsSummary(rule);
  if (params) parts.push(params);
  parts.push(rule.cooldownMinutes > 0 ? `cooldown ${formatMinutes(rule.cooldownMinutes)}` : "no cooldown");
  if (rule.notifyOnResolve) parts.push("notice when it clears");
  return parts.join(" · ");
}

export type SubjectLink = { label: string; description: string; href: string; /** A button label, e.g. "View certificates". */ action: string };

/** Where to look more closely at what an alert is about, from its subject key. */
export function subjectLink(subjectKey: string, hostNames: ReadonlyMap<number, string>): SubjectLink | null {
  const colon = subjectKey.indexOf(":");
  const kind = colon >= 0 ? subjectKey.slice(0, colon) : subjectKey;
  const value = colon >= 0 ? subjectKey.slice(colon + 1) : "";
  switch (kind) {
    case "managed_certificate":
      return { label: value, description: "The certificate Caddy serves for this name", href: "/certificates", action: "View certificates" };
    case "certificate":
    case "ca_certificate":
    case "client_certificate":
      return { label: "Certificates", description: "Expiry, renewal and the hosts that use it", href: "/certificates", action: "View certificates" };
    case "upstream":
      return { label: value, description: "Proxy hosts that send traffic to this upstream", href: `/proxy-hosts?search=${encodeURIComponent(value)}`, action: "Find the hosts" };
    case "proxy_host": {
      const name = hostNames.get(Number(value));
      return name
        ? { label: name, description: "The proxy host and its settings", href: `/proxy-hosts?search=${encodeURIComponent(name)}`, action: "Open the host" }
        : null;
    }
    case "hosts":
      return { label: "Traffic analytics", description: "Status codes, paths and upstreams", href: "/analytics", action: "Open analytics" };
    case "waf":
      return { label: "Security events", description: "The blocked requests and the rules that matched", href: "/security", action: "Show security events" };
    case "instance":
    case "rollout":
      return { label: "Fleet", description: "Instances, drift and rollouts", href: "/fleet", action: "Open the fleet" };
    case "backup_destination":
      return { label: "Backups", description: "Destinations and recent runs", href: "/backups", action: "Open backups" };
    case "change_request":
      return { label: `Change request #${value}`, description: "The change waiting for approval", href: `/approvals?request=${encodeURIComponent(value)}`, action: "Open the request" };
    case "access_review":
      return { label: "Access reviews", description: "The campaign and its open items", href: "/access-reviews", action: "Open access reviews" };
    default:
      return null;
  }
}

/** The audit log around a time window (30 minutes either side). */
export function auditLogAround(from: string, to: string): string {
  const pad = 30 * 60_000;
  const start = new Date(Date.parse(from) - pad).toISOString();
  const end = new Date(Date.parse(to) + pad).toISOString();
  return `/audit-log?from=${encodeURIComponent(start)}&to=${encodeURIComponent(end)}`;
}

function hostOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/** Where a channel delivers, without secrets: the host or target, and a second line. */
export function channelDestination(channel: AlertChannelView): { target: string; detail: string } {
  switch (channel.type) {
    case "email": {
      const config = channel.config as EmailChannelView;
      return {
        target: `${config.host}:${config.port}`,
        detail: `${config.secure ? "Implicit TLS" : "STARTTLS when offered"} · to ${config.to.join(", ")}`,
      };
    }
    case "slack":
    case "teams": {
      const config = channel.config as WebhookUrlChannelView;
      return {
        target: hostOf(config.webhookUrlHint) ?? "URL missing",
        detail: `${channel.type === "slack" ? "Incoming webhook" : "Workflows webhook"}${config.hasWebhookUrl ? ", URL stored" : ", no URL stored"}`,
      };
    }
    case "webhook": {
      const config = channel.config as WebhookChannelView;
      return { target: hostOf(config.urlHint) ?? "URL missing", detail: `JSON POST${config.hasHmacSecret ? " · signed" : ""}` };
    }
    case "pagerduty": {
      const config = channel.config as PagerDutyChannelView;
      return {
        target: `Events API v2, ${config.region === "eu" ? "EU" : "US"} region`,
        detail: config.hasRoutingKey ? "Integration key stored · opens and closes incidents" : "No integration key stored",
      };
    }
    case "ntfy": {
      const config = channel.config as NtfyChannelView;
      return {
        target: hostOf(config.serverUrl) ?? config.serverUrl,
        detail: `Topic ${config.topic} · ${config.hasToken ? "access token stored" : "no access token"}`,
      };
    }
    case "telegram": {
      const config = channel.config as TelegramChannelView;
      return {
        target: `Chat ${config.chatId}`,
        detail: config.hasBotToken ? "Bot token stored" : "No bot token stored",
      };
    }
  }
}

export function channelTypeLabel(channel: AlertChannelView): string {
  return CHANNEL_TYPE_LABELS[channel.type];
}

/** One alert from when it fired to when it resolved (or still firing). */
export type AlertEpisode = {
  /** The firing event's id. */
  id: number;
  ruleId: number;
  ruleName: string;
  ruleType: string;
  subjectKey: string;
  severity: Severity;
  title: string;
  message: string;
  explanation: string | null;
  firedAt: string;
  resolvedAt: string | null;
  /** Whether the firing notification went out (not held back by the cooldown, a mute or a dismissal; a channel was set). */
  notified: boolean;
  /** Held back by a mute or dismissal. */
  silenced: AlertEventView["silenced"];
  deliveries: AlertEventView["deliveries"];
  /** The resolve event, when it is in the events given. */
  resolve: { at: string; notified: boolean; deliveries: AlertEventView["deliveries"] } | null;
};

/**
 * Episodes that fired at or after `since`, newest first: each firing event
 * with the resolve event that ended it (same rule and subject, recorded at
 * the firing event's resolvedAt).
 */
export function buildEpisodes(events: readonly AlertEventView[], since: number): AlertEpisode[] {
  const resolves = new Map<string, AlertEventView>();
  for (const event of events) {
    if (event.status === "resolved") resolves.set(`${event.ruleId}\u0000${event.subjectKey}\u0000${event.createdAt}`, event);
  }
  return events
    .filter((event) => event.status === "firing" && Date.parse(event.createdAt) >= since)
    .map((event): AlertEpisode => {
      const resolved = event.resolvedAt ? resolves.get(`${event.ruleId}\u0000${event.subjectKey}\u0000${event.resolvedAt}`) : undefined;
      return {
        id: event.id,
        ruleId: event.ruleId,
        ruleName: event.ruleName,
        ruleType: event.ruleType,
        subjectKey: event.subjectKey,
        severity: event.severity,
        title: event.title,
        message: event.message,
        explanation: event.explanation,
        firedAt: event.createdAt,
        resolvedAt: event.resolvedAt,
        notified: event.notified,
        silenced: event.silenced ?? null,
        deliveries: event.deliveries,
        resolve: event.resolvedAt
          ? { at: event.resolvedAt, notified: resolved?.notified ?? false, deliveries: resolved?.deliveries ?? [] }
          : null,
      };
    })
    .sort((a, b) => b.firedAt.localeCompare(a.firedAt) || b.id - a.id);
}
