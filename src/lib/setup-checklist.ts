/**
 * The setup checklist of a fresh install: five steps whose state is read from
 * the data (a step is done when what it asks for exists), plus "mark as
 * done" for the steps the data cannot tell about or someone chose to skip.
 *
 * - domain: Caddy holds a valid certificate it obtained itself for at least
 *   one host (so a domain points here and ports 80/443 are reachable); this
 *   reads the cached TLS checks of src/lib/managed-certificates.ts.
 * - first_proxy_host: a proxy host exists.
 * - analytics: ClickHouse analytics is configured.
 * - second_user: there are at least two users.
 * - single_sign_on: an enabled OAuth/OIDC provider, SAML provider or LDAP
 *   directory exists.
 *
 * Marks and the dismissal are stored under the settings key
 * "setup_checklist" on this node only (not synced: it is about setting up
 * this install). Marks of steps this release does not have (npm_import, from
 * releases with the Nginx Proxy Manager import) are ignored when read and
 * dropped at the next change. Changing them is audited.
 */
import { and, count, eq } from "drizzle-orm";
import { appDb, nowIso } from "./db";
import { ldapDirectories, oauthProviders, proxyHosts, samlProviders, users } from "./db/schema";
import { getSetting, setSetting } from "./settings";
import { logAuditEvent } from "./audit";
import { ApiValidationError } from "./api-errors";
import { isAnalyticsEnabled } from "./clickhouse/client";
import { getManagedCertificates } from "./managed-certificates";

export const SETUP_CHECKLIST_KEY = "setup_checklist";

export const SETUP_STEPS = ["domain", "first_proxy_host", "analytics", "second_user", "single_sign_on"] as const;
export type SetupStepKey = (typeof SETUP_STEPS)[number];

type StepDefinition = { title: string; description: string; action: { label: string; route: string } | null };

const STEP_DEFINITIONS: Record<SetupStepKey, StepDefinition> = {
  domain: {
    title: "Point a domain at this server",
    description:
      "Create an A or AAAA record for each domain you will serve, pointing at this server's public address. Ports 80 and 443 must be " +
      "reachable from the internet so certificates can be issued.",
    action: null,
  },
  first_proxy_host: {
    title: "Add your first proxy host",
    description: "Send a domain to a service on your network. The certificate is requested as soon as you save.",
    action: { label: "New proxy host", route: "/proxy-hosts" },
  },
  analytics: {
    title: "Turn on analytics",
    description:
      "Traffic and WAF charts need the ClickHouse database. Set a CLICKHOUSE_PASSWORD in .env, then run docker compose up -d.",
    action: null,
  },
  second_user: {
    title: "Invite a teammate",
    description: "Create an account for each person who manages this install, so the audit log can tell people apart.",
    action: { label: "Add a user", route: "/users" },
  },
  single_sign_on: {
    title: "Set up single sign-on",
    description: "Sign in through an OpenID Connect or SAML provider, or an LDAP directory.",
    action: { label: "Single sign-on", route: "/sso" },
  },
};

export type SetupStepView = {
  key: SetupStepKey;
  title: string;
  description: string;
  done: boolean;
  /** data: what the step asks for exists; manual: someone marked it done; null while not done. */
  doneBy: "data" | "manual" | null;
  markedAt: string | null;
  action: { label: string; route: string } | null;
};

export type SetupChecklistView = {
  steps: SetupStepView[];
  done: number;
  total: number;
  /** Every step is done. */
  complete: boolean;
  dismissed: boolean;
  dismissedAt: string | null;
};

type Stored = { marked: Partial<Record<SetupStepKey, { at: string; userId: number | null }>>; dismissedAt: string | null };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readStored(): Promise<Stored> {
  const value = await getSetting<unknown>(SETUP_CHECKLIST_KEY);
  const stored: Stored = { marked: {}, dismissedAt: null };
  if (!isRecord(value)) return stored;
  if (isRecord(value.marked)) {
    for (const key of SETUP_STEPS) {
      const entry = value.marked[key];
      if (isRecord(entry) && typeof entry.at === "string") {
        stored.marked[key] = { at: entry.at, userId: typeof entry.userId === "number" ? entry.userId : null };
      }
    }
  }
  stored.dismissedAt = typeof value.dismissedAt === "string" ? value.dismissedAt : null;
  return stored;
}

function countOf(rows: { value: number }[]): number {
  return rows[0]?.value ?? 0;
}

/** What the data says about each step. */
async function dataState(): Promise<Record<SetupStepKey, boolean>> {
  const [hosts, people, oauth, saml, ldap] = await Promise.all([
    appDb.select({ value: count() }).from(proxyHosts),
    appDb.select({ value: count() }).from(users),
    appDb.select({ value: count() }).from(oauthProviders).where(eq(oauthProviders.enabled, true)),
    appDb.select({ value: count() }).from(samlProviders).where(eq(samlProviders.enabled, true)),
    appDb.select({ value: count() }).from(ldapDirectories).where(and(eq(ldapDirectories.enabled, true))),
  ]);
  const managed = await getManagedCertificates({ cachedOnly: true }).catch(() => null);
  const domain = managed?.certificates.some((status) => status.state === "valid" || status.state === "renewal_due") ?? false;
  return {
    domain,
    first_proxy_host: countOf(hosts) > 0,
    analytics: isAnalyticsEnabled(),
    second_user: countOf(people) >= 2,
    single_sign_on: countOf(oauth) + countOf(saml) + countOf(ldap) > 0,
  };
}

export async function getSetupChecklist(): Promise<SetupChecklistView> {
  const [stored, data] = await Promise.all([readStored(), dataState()]);
  const steps = SETUP_STEPS.map((key): SetupStepView => {
    const definition = STEP_DEFINITIONS[key];
    const marked = stored.marked[key] ?? null;
    const doneBy = data[key] ? "data" : marked ? "manual" : null;
    return {
      key,
      title: definition.title,
      description: definition.description,
      done: doneBy !== null,
      doneBy,
      markedAt: marked?.at ?? null,
      action: definition.action,
    };
  });
  const done = steps.filter((step) => step.done).length;
  return {
    steps,
    done,
    total: steps.length,
    complete: steps.every((step) => step.done),
    dismissed: stored.dismissedAt !== null,
    dismissedAt: stored.dismissedAt,
  };
}

/**
 * {steps?: {<step>: true|false}, dismissed?: true|false}: marks steps done or
 * not done, and hides or shows the checklist.
 */
export async function updateSetupChecklist(body: unknown, actorUserId: number): Promise<SetupChecklistView> {
  if (!isRecord(body)) throw new ApiValidationError("Request body must be a JSON object");
  for (const key of Object.keys(body)) {
    if (key !== "steps" && key !== "dismissed") throw new ApiValidationError(`Unknown field "${key.slice(0, 64)}"`);
  }
  const stored = await readStored();
  const changes: string[] = [];
  if (body.steps !== undefined) {
    if (!isRecord(body.steps)) throw new ApiValidationError("steps must be an object of step names and true or false");
    for (const [key, value] of Object.entries(body.steps)) {
      if (!(SETUP_STEPS as readonly string[]).includes(key)) throw new ApiValidationError(`steps: unknown step "${key.slice(0, 64)}"`);
      if (typeof value !== "boolean") throw new ApiValidationError(`steps.${key} must be true or false`);
      const step = key as SetupStepKey;
      if (value && !stored.marked[step]) {
        stored.marked[step] = { at: nowIso(), userId: actorUserId };
        changes.push(`marked "${STEP_DEFINITIONS[step].title}" as done`);
      } else if (!value && stored.marked[step]) {
        delete stored.marked[step];
        changes.push(`marked "${STEP_DEFINITIONS[step].title}" as not done`);
      }
    }
  }
  if (body.dismissed !== undefined) {
    if (typeof body.dismissed !== "boolean") throw new ApiValidationError("dismissed must be true or false");
    if (body.dismissed && stored.dismissedAt === null) {
      stored.dismissedAt = nowIso();
      changes.push("hid the setup checklist");
    } else if (!body.dismissed && stored.dismissedAt !== null) {
      stored.dismissedAt = null;
      changes.push("showed the setup checklist again");
    }
  }
  if (changes.length > 0) {
    await setSetting(SETUP_CHECKLIST_KEY, stored);
    await logAuditEvent({
      userId: actorUserId,
      action: "setup_checklist_updated",
      entityType: "setup_checklist",
      summary: `Setup checklist: ${changes.join(", ")}`,
      data: { marked: Object.keys(stored.marked), dismissed: stored.dismissedAt !== null },
    });
  }
  return getSetupChecklist();
}
