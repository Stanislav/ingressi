"use client";

import { useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/proxy-hosts/editor/controls";
import { describeChallenge, effectiveChallenge, type DnsProviderChoices } from "@/src/lib/dns-provider-choice";
import { saveManagedCertificateAction, type SavedManagedCertificate } from "@/app/(dashboard)/certificates/actions";

/** A certificate Caddy obtains by itself, as the sheet edits it. */
export type ManagedCertificateView = { id: number; name: string; domains: string[]; provider: string | null };

type Props = {
  open: boolean;
  /** The certificate being changed, or null to create one. */
  cert: ManagedCertificateView | null;
  choices: DnsProviderChoices;
  /** What a new certificate starts with. */
  initial?: { name: string; domains: string[]; provider: string | null };
  onClose: () => void;
  onSaved?: (cert: SavedManagedCertificate) => void;
};

function parseDomains(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((domain) => domain.trim())
    .filter(Boolean);
}

export function ManagedCertificateSheet({ open, ...props }: Props) {
  return (
    <Sheet open={open} onOpenChange={(next) => { if (!next) props.onClose(); }}>
      <SheetContent side="right" className="flex w-full flex-col gap-6 overflow-y-auto sm:w-[480px] sm:max-w-[480px]">
        <ManagedCertificateForm {...props} />
      </SheetContent>
    </Sheet>
  );
}

/** Mounted with the open sheet, so every opening starts from the certificate's own values. */
function ManagedCertificateForm({ cert, choices, initial, onClose, onSaved }: Omit<Props, "open">) {
  const editing = cert !== null;
  const start = cert ?? initial ?? { name: "", domains: [], provider: null };
  const [name, setName] = useState(start.name);
  const [domains, setDomains] = useState(start.domains.join("\n"));
  const [provider, setProvider] = useState(start.provider && choices.providers.some((option) => option.name === start.provider) ? start.provider : "");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const chosen = describeChallenge(effectiveChallenge(choices, provider || null));
  const defaultLabel = choices.providers.find((option) => option.name === choices.defaultProvider)?.label ?? null;

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    startTransition(async () => {
      try {
        const result = await saveManagedCertificateAction({
          id: cert?.id,
          name,
          domainNames: parseDomains(domains),
          provider: provider || null,
        });
        if (!result.ok) {
          setError(result.error);
          return;
        }
        onSaved?.(result.certificate);
        onClose();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "The certificate could not be saved.");
      }
    });
  }

  return (
    <>
      <SheetHeader>
        <SheetTitle>{editing ? "Edit certificate" : "New managed certificate"}</SheetTitle>
      </SheetHeader>
      <form onSubmit={handleSubmit} className="flex flex-1 flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="mc-name">Name</Label>
          <Input id="mc-name" value={name} onChange={(event) => setName(event.target.value)} required autoFocus />
        </div>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="mc-domains">Domains (one per line)</Label>
          <Textarea
            id="mc-domains"
            value={domains}
            onChange={(event) => setDomains(event.target.value)}
            rows={3}
            placeholder={"app.example.com\n*.example.com"}
            className="font-mono text-xs"
          />
        </div>

        {choices.providers.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="mc-provider">DNS provider</Label>
            <NativeSelect id="mc-provider" value={provider} onChange={(event) => setProvider(event.target.value)}>
              <option value="">{defaultLabel ? `Default (${defaultLabel})` : "None (HTTP-01)"}</option>
              {choices.providers.map((option) => (
                <option key={option.name} value={option.name}>
                  {option.label}
                </option>
              ))}
            </NativeSelect>
            <p className="m-0 text-xs text-muted-foreground" data-testid="managed-certificate-challenge">
              Uses {chosen}
            </p>
          </div>
        )}

        {error && (
          <p role="alert" className="m-0 text-sm text-bad">
            {error}
          </p>
        )}

        <div className="mt-auto flex justify-end gap-2 pt-2">
          <Button type="button" variant="outline" onClick={onClose} disabled={isPending}>
            Cancel
          </Button>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving…" : editing ? "Save changes" : "Create certificate"}
          </Button>
        </div>
      </form>
    </>
  );
}
