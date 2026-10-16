// SPDX-License-Identifier: Elastic-2.0
/**
 * Notices: one-off messages that are not alerts (e.g. "the monthly compliance
 * evidence pack is ready"), sent through the alert channels with the same
 * transport rules (10 s timeout, no redirects, application-authored errors).
 * PagerDuty channels never receive notices: they open incidents.
 */
import { BRAND_NAME } from "@/src/lib/brand";
import { brandName } from "@/ee/white-label/store";
import {
  ChannelSecretsUnavailableError,
  getChannelRows,
  recordChannelDelivery,
  resolveChannel,
  type ResolvedChannel,
} from "./channels";
import { DeliveryError, describeFetchError, describeSmtpError, postJson, sendEmailMessage, telegramEndpoint, type DeliveryResult } from "./deliver";
import { cleanText, escapeHtml, escapeSlack, escapeTeams, signWebhook } from "./format";

export type Notice = {
  /** Machine name of what happened, for webhook receivers (e.g. "compliance_reports_generated"). */
  event: string;
  title: string;
  /** Short paragraphs or list lines. */
  lines: string[];
  /** Where to look in the dashboard (absolute URL), if any. */
  link: string | null;
  /** Structured data for webhook receivers; never secrets. */
  data: Record<string, unknown>;
  at: string;
};

export type NoticeDelivery = { channelId: number; channelName: string; ok: boolean; error: string | null };

function text(notice: Notice): string {
  return [cleanText(notice.title, 300), "", ...notice.lines.map((line) => cleanText(line, 1000, true)), ...(notice.link ? ["", notice.link] : [])].join("\n");
}

async function send(channel: ResolvedChannel, notice: Notice): Promise<void> {
  switch (channel.type) {
    case "email": {
      const html = [
        `<p><strong>${escapeHtml(cleanText(notice.title, 300))}</strong></p>`,
        ...notice.lines.map((line) => `<p>${escapeHtml(cleanText(line, 1000, true)).replace(/\n/g, "<br>")}</p>`),
        notice.link ? `<p><a href="${escapeHtml(notice.link)}">${escapeHtml(notice.link)}</a></p>` : "",
        `<p style="color:#999">Sent by ${escapeHtml(brandName())}</p>`,
      ].filter(Boolean);
      await sendEmailMessage(channel, { subject: cleanText(`[${brandName()}] ${notice.title}`, 250), text: text(notice), html: html.join("\n") });
      return;
    }
    case "slack":
      await postJson(
        channel.secrets.webhookUrl,
        JSON.stringify({ text: [`*${escapeSlack(cleanText(notice.title, 300))}*`, ...notice.lines.map((line) => escapeSlack(cleanText(line, 1000, true))), ...(notice.link ? [notice.link] : [])].join("\n") })
      );
      return;
    case "teams":
      await postJson(
        channel.secrets.webhookUrl,
        JSON.stringify({
          type: "message",
          attachments: [
            {
              contentType: "application/vnd.microsoft.card.adaptive",
              content: {
                $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
                type: "AdaptiveCard",
                version: "1.4",
                body: [
                  { type: "TextBlock", text: escapeTeams(cleanText(notice.title, 300)), weight: "Bolder", size: "Medium", wrap: true },
                  ...notice.lines.map((line) => ({ type: "TextBlock", text: escapeTeams(cleanText(line, 1000, true)), wrap: true })),
                ],
                ...(notice.link ? { actions: [{ type: "Action.OpenUrl", title: "Open", url: notice.link }] } : {}),
              },
            },
          ],
        })
      );
      return;
    case "webhook": {
      const body = JSON.stringify({ version: 1, source: BRAND_NAME.toLowerCase(), event: notice.event, title: notice.title, lines: notice.lines, link: notice.link, data: notice.data, at: notice.at });
      const timestamp = String(Math.floor(Date.parse(notice.at) / 1000));
      const headers: Record<string, string> = { "X-Ingressi-Timestamp": timestamp };
      if (channel.secrets.hmacSecret) headers["X-Ingressi-Signature"] = signWebhook(channel.secrets.hmacSecret, timestamp, body);
      await postJson(channel.secrets.url, body, headers);
      return;
    }
    case "ntfy": {
      const headers: Record<string, string> = {};
      if (channel.secrets.token) headers.Authorization = `Bearer ${channel.secrets.token}`;
      await postJson(
        `${channel.config.serverUrl}/`,
        JSON.stringify({ topic: channel.config.topic, title: cleanText(notice.title, 250), message: text(notice).slice(0, 3500), priority: 3, ...(notice.link ? { click: notice.link } : {}) }),
        headers
      );
      return;
    }
    case "telegram":
      await postJson(
        telegramEndpoint(channel.secrets.botToken),
        JSON.stringify({ chat_id: channel.config.chatId, text: text(notice).slice(0, 4000), disable_web_page_preview: true })
      );
      return;
    case "pagerduty":
      throw new DeliveryError("Notices are not sent to PagerDuty");
  }
}

/** Sends a notice through one channel; never throws. */
export async function deliverNoticeToChannel(channel: ResolvedChannel, notice: Notice): Promise<DeliveryResult> {
  try {
    await send(channel, notice);
    return { ok: true, error: null };
  } catch (error) {
    return { ok: false, error: channel.type === "email" && !(error instanceof DeliveryError) ? describeSmtpError(error) : describeFetchError(error) };
  }
}

export type NoticeDependencies = { deliver: typeof deliverNoticeToChannel };

/** Sends a notice to the enabled channels among `channelIds` (PagerDuty skipped), concurrently. */
export async function sendNotice(channelIds: readonly number[], notice: Notice, deps: NoticeDependencies = { deliver: deliverNoticeToChannel }): Promise<NoticeDelivery[]> {
  if (channelIds.length === 0) return [];
  const rows = (await getChannelRows(channelIds)).filter((row) => row.enabled && row.type !== "pagerduty");
  return Promise.all(
    rows.map(async (row) => {
      let result: DeliveryResult;
      try {
        result = await deps.deliver(resolveChannel(row), notice);
      } catch (error) {
        result = { ok: false, error: error instanceof ChannelSecretsUnavailableError ? error.message : "The notice could not be sent" };
      }
      await recordChannelDelivery(row.id, result.error, notice.at).catch(() => undefined);
      return { channelId: row.id, channelName: row.name, ok: result.ok, error: result.error };
    })
  );
}
