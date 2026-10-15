"use server";

import { revalidatePath } from "next/cache";
import { requirePermission } from "@/src/lib/auth";
import { assertCanCreateCertificate, assertCertificateWritable } from "@/src/lib/access-scope";
import { createCertificate, deleteCertificate, getCertificate, updateCertificate } from "@/src/lib/models/certificates";
import { ApiClientError } from "@/src/lib/api-errors";
import { CaddyApplyError } from "@/src/lib/caddy-apply-error";
import { normalizeProxyHostDomains } from "@/src/lib/proxy-host-domains";
import { getDnsProviderSettings } from "@/src/lib/settings";

function parseDomains(value: FormDataEntryValue | null): string[] {
  if (!value || typeof value !== "string") {
    return [];
  }
  return value
    .replace(/\n/g, ",")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export async function createCertificateAction(formData: FormData) {
  const session = await requirePermission("certificates:write");
  assertCanCreateCertificate(session.access);
  const userId = Number(session.user.id);
  const type = String(formData.get("type") ?? "managed") as "managed" | "imported";
  await createCertificate(
    {
      name: String(formData.get("name") ?? "Certificate"),
      type,
      domainNames: parseDomains(formData.get("domain_names")),
      autoRenew: type === "managed" ? formData.get("auto_renew") === "on" : false,
      certificatePem: type === "imported" ? String(formData.get("certificate_pem") ?? "") : null,
      privateKeyPem: type === "imported" ? String(formData.get("private_key_pem") ?? "") : null
    },
    userId
  );
  revalidatePath("/certificates");
}

export async function updateCertificateAction(id: number, formData: FormData) {
  const session = await requirePermission("certificates:write");
  await assertCertificateWritable(session.access, id);
  const userId = Number(session.user.id);
  const type = formData.get("type") ? (String(formData.get("type")) as "managed" | "imported") : undefined;
  await updateCertificate(
    id,
    {
      name: formData.get("name") ? String(formData.get("name")) : undefined,
      type,
      domainNames: formData.get("domain_names") ? parseDomains(formData.get("domain_names")) : undefined,
      autoRenew: formData.has("auto_renew_present") ? formData.get("auto_renew") === "on" : undefined,
      certificatePem: formData.get("certificate_pem") ? String(formData.get("certificate_pem")) : undefined,
      privateKeyPem: formData.get("private_key_pem") ? String(formData.get("private_key_pem")) : undefined
    },
    userId
  );
  revalidatePath("/certificates");
}

export type ManagedCertificateInput = {
  /** Set to change a managed certificate; omitted to create one. */
  id?: number;
  name: string;
  domainNames: string[];
  /** The DNS provider to obtain it with, by the name it has under Certificate settings; null uses the default. */
  provider: string | null;
};

/** What the sheets that save a managed certificate need of the saved one. */
export type SavedManagedCertificate = { id: number; name: string; domains: string[]; provider: string | null };

export type SaveManagedCertificateResult = { ok: true; certificate: SavedManagedCertificate } | { ok: false; error: string };

/**
 * Creates or changes a certificate Caddy obtains by itself (ACME), optionally
 * with its own DNS provider instead of the default. Errors the person can act
 * on come back as `error`.
 */
export async function saveManagedCertificateAction(input: ManagedCertificateInput): Promise<SaveManagedCertificateResult> {
  const session = await requirePermission("certificates:write");
  const editing = input.id !== undefined;
  if (editing) await assertCertificateWritable(session.access, input.id!);
  else assertCanCreateCertificate(session.access);
  const userId = Number(session.user.id);

  const name = String(input.name ?? "").trim();
  if (!name) return { ok: false, error: "Enter a name for the certificate." };

  let domains: string[];
  try {
    domains = normalizeProxyHostDomains(Array.isArray(input.domainNames) ? input.domainNames.map(String) : []);
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Enter at least one valid domain." };
  }

  const provider = input.provider ? String(input.provider).trim() : null;
  if (provider) {
    const settings = await getDnsProviderSettings();
    if (!settings?.providers[provider]) {
      return { ok: false, error: "That DNS provider is not set up. Add it under Certificate settings first." };
    }
  }

  if (editing) {
    const existing = await getCertificate(input.id!);
    if (!existing) return { ok: false, error: "That certificate no longer exists." };
    if (existing.type !== "managed") return { ok: false, error: "Only certificates Caddy obtains can be changed here." };
  }

  try {
    const saved = editing
      ? await updateCertificate(input.id!, { name, domainNames: domains, providerOptions: provider ? { provider } : null }, userId)
      : await createCertificate(
          { name, type: "managed", domainNames: domains, autoRenew: true, providerOptions: provider ? { provider } : null },
          userId
        );
    revalidatePath("/certificates");
    return {
      ok: true,
      certificate: {
        id: saved.id,
        name: saved.name,
        domains: saved.domainNames,
        provider: typeof saved.providerOptions?.provider === "string" ? saved.providerOptions.provider : null,
      },
    };
  } catch (error) {
    if (error instanceof ApiClientError) return { ok: false, error: error.message };
    if (error instanceof CaddyApplyError) return { ok: false, error: `The certificate was saved, but Caddy did not accept the configuration: ${error.message}` };
    throw error;
  }
}

/** Errors the person can act on come back as `error` (a thrown message would not reach the browser in production). */
export async function deleteCertificateAction(id: number): Promise<{ ok: true } | { ok: false; error: string }> {
  const session = await requirePermission("certificates:write");
  await assertCertificateWritable(session.access, id);
  const userId = Number(session.user.id);
  try {
    await deleteCertificate(id, userId);
  } catch (error) {
    if (error instanceof ApiClientError) return { ok: false, error: error.message };
    throw error;
  }
  revalidatePath("/certificates");
  return { ok: true };
}
