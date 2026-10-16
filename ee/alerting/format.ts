// SPDX-License-Identifier: Elastic-2.0
/**
 * Notification payloads per channel type. Pure functions, no I/O.
 *
 * Titles and messages are written by the evaluators; they may quote names an
 * administrator typed and, for WAF alerts, host names from requests, so every
 * channel escapes them for its own markup. AI explanations are always labeled.
 */
import { createHash, createHmac } from "node:crypto";
import { BRAND_NAME } from "@/src/lib/brand";
import { brandName } from "@/ee/white-label/store";
import type { Severity } from "./types";

export const AI_EXPLANATION_LABEL = "AI-generated explanation";

export type AlertNotification = {
  kind: "firing" | "resolved" | "test";
  ruleId: number | null;
  ruleName: string;
  ruleType: string;
  subjectKey: string;
  severity: Severity;
  title: string;
  message: string;
  facts: Record<string, unknown>;
  explanation: string | null;
  eventId: number | null;
  /** ISO 8601 */
  at: string;
};

const KIND_LABEL: Record<AlertNotification["kind"], string> = {
  firing: "FIRING",
  resolved: "RESOLVED",
  test: "TEST",
};

/** Removes control characters (keeping newlines when `multiline`) and caps the length. */
export function cleanText(value: string, max: number, multiline = false): string {
  const cleaned = multiline
    ? value.replace(/\r\n?/g, "\n").replace(/(?!\n)\p{Cc}/gu, "").replace(/\n{3,}/g, "\n\n")
    : value.replace(/\p{Cc}+/gu, " ");
  const trimmed = cleaned.trim();
  return trimmed.length > max ? `${trimmed.slice(0, max - 1)}…` : trimmed;
}

export function headline(n: AlertNotification): string {
  return cleanText(`[${KIND_LABEL[n.kind]}] ${n.title}`, 250);
}

function ruleLine(n: AlertNotification): string | null {
  return n.kind === "test" ? null : `Rule: ${cleanText(n.ruleName, 100)}`;
}

/** The plain-text body shared by e-mail, ntfy and the webhook. */
export function plainTextBody(n: AlertNotification): string {
  const lines = [cleanText(n.message, 2000, true), ""];
  const rule = ruleLine(n);
  if (rule) lines.push(rule);
  lines.push(`Time: ${n.at}`);
  if (n.explanation) {
    lines.push("", `${AI_EXPLANATION_LABEL}:`, cleanText(n.explanation, 1500, true));
  }
  lines.push("", `Sent by ${brandName()}`);
  return lines.join("\n");
}

// ── Slack ──────────────────────────────────────────────────────────────

/** Slack mrkdwn control characters; escaping them also disables @channel-style mentions. */
export function escapeSlack(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const SLACK_EMOJI: Record<AlertNotification["kind"], string> = {
  firing: ":rotating_light:",
  resolved: ":white_check_mark:",
  test: ":wave:",
};

export function buildSlackPayload(n: AlertNotification): { text: string } {
  const parts = [
    `${SLACK_EMOJI[n.kind]} *${escapeSlack(headline(n))}*`,
    escapeSlack(cleanText(n.message, 2000, true)),
  ];
  const rule = ruleLine(n);
  parts.push(`_${escapeSlack([rule, `Time: ${n.at}`].filter(Boolean).join(" · "))}_`);
  if (n.explanation) {
    parts.push(`*${AI_EXPLANATION_LABEL}:* ${escapeSlack(cleanText(n.explanation, 1500, true))}`);
  }
  return { text: parts.join("\n") };
}

// ── Microsoft Teams (Workflows / incoming webhook, Adaptive Card) ─────

/** Adaptive Card TextBlocks render a Markdown subset; neutralise link and emphasis syntax. */
export function escapeTeams(text: string): string {
  return text.replace(/([\\`*_[\]()<>#])/g, "\\$1");
}

export function buildTeamsPayload(n: AlertNotification): Record<string, unknown> {
  const color = n.kind === "resolved" ? "Good" : n.kind === "test" ? "Accent" : n.severity === "critical" ? "Attention" : "Warning";
  const facts = [
    ...(n.kind === "test" ? [] : [{ title: "Rule", value: escapeTeams(cleanText(n.ruleName, 100)) }]),
    { title: "Severity", value: n.severity },
    { title: "Time", value: n.at },
  ];
  const body: Record<string, unknown>[] = [
    { type: "TextBlock", text: escapeTeams(headline(n)), weight: "Bolder", size: "Medium", color, wrap: true },
    { type: "TextBlock", text: escapeTeams(cleanText(n.message, 2000, true)), wrap: true },
    { type: "FactSet", facts },
  ];
  if (n.explanation) {
    body.push(
      { type: "TextBlock", text: AI_EXPLANATION_LABEL, weight: "Bolder", spacing: "Medium", wrap: true },
      { type: "TextBlock", text: escapeTeams(cleanText(n.explanation, 1500, true)), wrap: true, isSubtle: true }
    );
  }
  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body,
        },
      },
    ],
  };
}

// ── Generic webhook ────────────────────────────────────────────────────

export function buildWebhookBody(n: AlertNotification): Record<string, unknown> {
  return {
    version: 1,
    // An identifier receivers match on: it keeps the real name under white-label branding.
    source: BRAND_NAME.toLowerCase(),
    status: n.kind,
    severity: n.severity,
    rule: n.kind === "test" ? null : { id: n.ruleId, name: n.ruleName, type: n.ruleType },
    subject: n.subjectKey,
    eventId: n.eventId,
    title: n.title,
    message: n.message,
    facts: n.facts,
    explanation: n.explanation ? { label: AI_EXPLANATION_LABEL, text: n.explanation } : null,
    at: n.at,
  };
}

/** `sha256=` + hex HMAC-SHA256 of `${timestamp}.${body}`. */
export function signWebhook(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

// ── PagerDuty Events API v2 ────────────────────────────────────────────

export function pagerDutyDedupKey(ruleId: number | null, subjectKey: string): string {
  const digest = createHash("sha256").update(subjectKey).digest("hex").slice(0, 24);
  // Not white-labelled: a rename would split open incidents from their resolve events.
  return `${BRAND_NAME.toLowerCase()}-${ruleId ?? "test"}-${digest}`;
}

const PAGERDUTY_SEVERITY: Record<Severity, string> = { critical: "critical", warning: "warning", info: "info" };

export function buildPagerDutyEvent(
  n: AlertNotification,
  routingKey: string,
  action: "trigger" | "resolve",
  dedupKey: string = pagerDutyDedupKey(n.ruleId, n.subjectKey)
): Record<string, unknown> {
  if (action === "resolve") {
    return { routing_key: routingKey, event_action: "resolve", dedup_key: dedupKey };
  }
  return {
    routing_key: routingKey,
    event_action: "trigger",
    dedup_key: dedupKey,
    payload: {
      summary: cleanText(n.title, 1024),
      source: brandName(),
      severity: PAGERDUTY_SEVERITY[n.severity],
      timestamp: n.at,
      component: n.subjectKey.slice(0, 255),
      group: cleanText(n.ruleName, 255),
      class: n.ruleType,
      custom_details: {
        message: n.message,
        facts: n.facts,
        ...(n.explanation ? { [AI_EXPLANATION_LABEL]: n.explanation } : {}),
      },
    },
  };
}

// ── ntfy ───────────────────────────────────────────────────────────────

export function buildNtfyMessage(n: AlertNotification, topic: string): Record<string, unknown> {
  const priority = n.kind === "firing" ? (n.severity === "critical" ? 5 : 4) : 3;
  const tags = n.kind === "firing" ? ["rotating_light"] : n.kind === "resolved" ? ["white_check_mark"] : ["wave"];
  return { topic, title: headline(n), message: plainTextBody(n), priority, tags };
}

// ── Telegram ───────────────────────────────────────────────────────────

/** Telegram caps a message at 4096 characters; sent as plain text (no parse_mode), so nothing needs escaping. */
export const TELEGRAM_MAX_CHARS = 4000;

export function buildTelegramMessage(n: AlertNotification, chatId: string): Record<string, unknown> {
  const text = `${headline(n)}\n\n${plainTextBody(n)}`;
  return { chat_id: chatId, text: cleanText(text, TELEGRAM_MAX_CHARS, true), disable_web_page_preview: true };
}

// ── E-mail ─────────────────────────────────────────────────────────────

export function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export function buildEmail(n: AlertNotification): { subject: string; text: string; html: string } {
  const subject = cleanText(`[${brandName()}] ${headline(n)}`, 250);
  const text = plainTextBody(n);
  const paragraphs = [
    `<p><strong>${escapeHtml(headline(n))}</strong></p>`,
    `<p>${escapeHtml(cleanText(n.message, 2000, true)).replace(/\n/g, "<br>")}</p>`,
    `<p style="color:#666">${escapeHtml([ruleLine(n), `Time: ${n.at}`].filter(Boolean).join(" · "))}</p>`,
  ];
  if (n.explanation) {
    paragraphs.push(
      `<p><strong>${AI_EXPLANATION_LABEL}:</strong><br>${escapeHtml(cleanText(n.explanation, 1500, true)).replace(/\n/g, "<br>")}</p>`
    );
  }
  paragraphs.push(`<p style="color:#999">Sent by ${escapeHtml(brandName())}</p>`);
  return { subject, text, html: paragraphs.join("\n") };
}

export function testNotification(at: Date = new Date()): AlertNotification {
  return {
    kind: "test",
    ruleId: null,
    ruleName: "Test",
    ruleType: "test",
    subjectKey: "test",
    severity: "info",
    title: `Test notification from ${brandName()}`,
    message: `If you can read this, ${brandName()} can deliver alerts to this channel.`,
    facts: {},
    explanation: null,
    eventId: null,
    at: at.toISOString(),
  };
}
