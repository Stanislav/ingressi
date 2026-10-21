"use client";

import { useState, useTransition, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Check, Copy, Plus } from "lucide-react";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { Checklist, type ChecklistItem } from "@/components/ui/Checklist";
import type { OverviewFirstRun, OverviewPermissions } from "@/src/lib/overview-shared";
import type { SetupChecklistView, SetupStepKey, SetupStepView } from "@/src/lib/setup-checklist";

/** The lines the analytics step asks to add to .env. */
export const ANALYTICS_ENV_LINES = "CLICKHOUSE_PASSWORD=<the generated password>";

const num = (text: string) => <span className="num">{text}</span>;

function stepDescription(step: SetupStepView): ReactNode {
  switch (step.key) {
    case "domain":
      return (
        <>
          Create an A or AAAA record for each domain, pointing at this server&apos;s public address. Ports {num("80")} and {num("443")} must
          be reachable from the internet for certificates to be issued.
        </>
      );
    case "first_proxy_host":
      return <>For example wiki.example.com to {num("10.0.4.21:3000")}.</>;
    case "analytics":
      return (
        <span id="step-analytics" className="flex scroll-mt-20 flex-col gap-2">
          <span>
            Add these lines to {num(".env")}, with a password from {num("openssl rand -base64 32")}, then run {num("docker compose up -d")}.
          </span>
          <pre className="num m-0 overflow-x-auto rounded-lg border border-line bg-panel2 px-3 py-2.5 text-xs leading-[18px] whitespace-pre text-foreground">
            {ANALYTICS_ENV_LINES}
          </pre>
        </span>
      );
    case "second_user":
      return <>One account per person, so the audit log can tell people apart.</>;
    case "single_sign_on":
      return <>Sign in through an OpenID Connect or SAML provider, or an LDAP directory.</>;
    default:
      return step.description;
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="secondary"
      size="sm"
      onClick={() => {
        try {
          void navigator.clipboard?.writeText(text).catch(() => undefined);
        } catch {
          // Copying is a convenience; the lines stay on the page.
        }
        setCopied(true);
      }}
    >
      {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function LinkButton({ href, children, primary = false }: { href: string; children: ReactNode; primary?: boolean }) {
  return (
    <Button asChild variant={primary ? "default" : "secondary"} size="sm">
      <Link href={href}>{children}</Link>
    </Button>
  );
}

/** The step's own action: the page where it is done, while it is not done. */
function stepAction(step: SetupStepView, permissions: OverviewPermissions): ReactNode {
  if (step.done) return null;
  switch (step.key) {
    case "first_proxy_host":
      return permissions.createProxyHost ? (
        <LinkButton href="/proxy-hosts?create=1" primary>
          <Plus aria-hidden="true" />
          New proxy host
        </LinkButton>
      ) : null;
    case "analytics":
      return <CopyButton text={ANALYTICS_ENV_LINES} />;
    case "second_user":
      return permissions.readUsers ? <LinkButton href="/users">Add a user</LinkButton> : null;
    case "single_sign_on":
      return permissions.readSso ? <LinkButton href="/sso">Single sign-on</LinkButton> : null;
    default:
      return null;
  }
}

async function saveChecklist(body: { steps?: Partial<Record<SetupStepKey, boolean>>; dismissed?: boolean }): Promise<SetupChecklistView | string> {
  try {
    const response = await fetch("/api/v1/setup-checklist", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await response.json().catch(() => null)) as (SetupChecklistView & { error?: string }) | null;
    if (!response.ok || !json) return json?.error ?? "Could not save the checklist. Try again.";
    return json;
  } catch {
    return "Could not reach the server. Try again.";
  }
}

/**
 * The setup checklist of a fresh install: five steps, done when the data
 * shows it or when someone marks them done (settings:write). The normal
 * overview takes over once every step is done or the checklist is hidden.
 */
export function SetupChecklist({ firstRun, permissions }: { firstRun: OverviewFirstRun; permissions: OverviewPermissions }) {
  const router = useRouter();
  const [checklist, setChecklist] = useState(firstRun.checklist);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const canMark = permissions.writeSettings;

  function save(body: Parameters<typeof saveChecklist>[0]) {
    setError(null);
    startTransition(async () => {
      const result = await saveChecklist(body);
      if (typeof result === "string") {
        setError(result);
        return;
      }
      setChecklist(result);
      if (result.complete || result.dismissed) router.refresh();
    });
  }

  const items: ChecklistItem[] = checklist.steps.map((step) => {
    const own = stepAction(step, permissions);
    const manual = step.doneBy === "manual";
    const mark =
      canMark && step.doneBy !== "data" ? (
        <Button
          type="button"
          variant="secondary"
          size="sm"
          aria-pressed={manual}
          disabled={pending}
          onClick={() => save({ steps: { [step.key]: !manual } })}
        >
          {manual ? "Done" : "Mark as done"}
          <span className="sr-only">: {step.title}</span>
        </Button>
      ) : null;
    return {
      id: step.key,
      label: step.title,
      description: stepDescription(step),
      done: step.done,
      action: own || mark ? (
        <>
          {own}
          {mark}
        </>
      ) : undefined,
    };
  });

  return (
    <div className="flex min-w-0 flex-[2_1_560px] flex-col gap-3" id="setup">
      {error && (
        <Banner tone="bad" live>
          {error}
        </Banner>
      )}
      <Checklist title="Set up this install" items={items} progressLabel="Setup steps done" />
      {canMark && (
        <div>
          <Button type="button" variant="ghost" size="sm" disabled={pending} onClick={() => save({ dismissed: true })}>
            Hide the checklist
          </Button>
        </div>
      )}
    </div>
  );
}
