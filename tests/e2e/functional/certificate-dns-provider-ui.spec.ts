/**
 * Functional test: choosing a DNS provider for a certificate from the dashboard
 * (#337), with the default provider left alone.
 *
 * Cloudflare is the default provider and GoDaddy a second one. The spec only
 * touches visible controls to pick the provider (the API sets the providers up
 * and reads results back), then reads the TLS automation policies Caddy is
 * serving:
 *   - the Certificates page creates a managed certificate with GoDaddy, edits it
 *     back to the default and again to GoDaddy;
 *   - the host editor of a new host names the default provider, creates a
 *     managed certificate with GoDaddy from its Certificate section and saves
 *     the host with it;
 *   - hosts that keep automatic TLS keep the default provider.
 */
import { test, expect, type Page } from '@playwright/test';
import { liveProviderFor } from '../../helpers/live-caddy';
import { fillHostBasics, openEditorSection, openHostEditor, openNewHost, saveHostEditor } from '../../helpers/proxy-api';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
// The Cloudflare module checks the token's shape when Caddy provisions it (40 URL-safe characters).
const FAKE_CLOUDFLARE_TOKEN = `e2e${'0'.repeat(37)}`;
const POLL = { timeout: 30_000, intervals: [500, 1000, 2000] };

type ApiCertificate = { id: number; name: string; domainNames: string[]; providerOptions: { provider: string } | null };

async function certificateNamed(page: Page, name: string): Promise<ApiCertificate | undefined> {
  const res = await page.request.get(`${API}/certificates`);
  expect(res.ok()).toBeTruthy();
  return ((await res.json()) as ApiCertificate[]).find((cert) => cert.name === name);
}

test.describe.serial('DNS provider per certificate, from the dashboard', () => {
  const stamp = Date.now();
  const certName = `Shop ${stamp}`;
  const certDomain = `shop-${stamp}.example`;
  const hostDomain = `editor-${stamp}.example`;
  const plainDomain = `plain-${stamp}.example`;
  const cleanup = { hosts: [] as number[], certs: [] as number[] };

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const res = await page.request.put(`${API}/settings/dns-provider`, {
      data: {
        providers: {
          cloudflare: { api_token: FAKE_CLOUDFLARE_TOKEN },
          godaddy: { api_token: 'e2e-key:e2e-secret' },
        },
        default: 'cloudflare',
      },
      headers: HEADERS,
    });
    expect(res.ok(), await res.text()).toBeTruthy();
    // A host that keeps automatic TLS: it must stay on the default provider throughout.
    const host = await page.request.post(`${API}/proxy-hosts`, {
      data: { name: `Plain ${plainDomain}`, domains: [plainDomain], upstreams: ['127.0.0.1:8080'] },
      headers: HEADERS,
    });
    expect(host.status(), await host.text()).toBe(201);
    cleanup.hosts.push((await host.json()).id as number);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    for (const id of cleanup.hosts) await page.request.delete(`${API}/proxy-hosts/${id}`, { headers: HEADERS }).catch(() => undefined);
    for (const id of cleanup.certs) await page.request.delete(`${API}/certificates/${id}`, { headers: HEADERS }).catch(() => undefined);
    await page.request.put(`${API}/settings/dns-provider`, { data: { providers: {}, default: null }, headers: HEADERS });
    await page.close();
  });

  test('the Certificates page creates a managed certificate that uses GoDaddy', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('button', { name: 'New managed certificate' }).click();
    const sheet = page.getByRole('dialog', { name: 'New managed certificate' });
    await sheet.getByLabel('Name', { exact: true }).fill(certName);
    await sheet.getByLabel('Domains (one per line)').fill(certDomain);

    // "Use global default" first, and the effective provider named before saving.
    const provider = sheet.getByLabel('DNS provider');
    await expect(provider).toHaveValue('');
    await expect(provider.locator('option').first()).toHaveText('Default (Cloudflare)');
    await expect(sheet.getByTestId('managed-certificate-challenge')).toHaveText('Uses DNS-01 with Cloudflare (default)');
    await provider.selectOption({ label: 'GoDaddy' });
    await expect(sheet.getByTestId('managed-certificate-challenge')).toHaveText('Uses DNS-01 with GoDaddy');
    await sheet.getByRole('button', { name: 'Create certificate' }).click();
    await expect(sheet).toBeHidden();

    const cert = await certificateNamed(page, certName);
    expect(cert, 'the certificate was created').toBeDefined();
    cleanup.certs.push(cert!.id);
    expect(cert).toMatchObject({ domainNames: [certDomain], providerOptions: { provider: 'godaddy' } });

    const row = page.getByRole('row').filter({ hasText: certName });
    await expect(row).toContainText('DNS-01');
    await expect(row).toContainText('GoDaddy');
  });

  test('a host using it gets GoDaddy in the live Caddy config, the default provider is untouched', async ({ page }) => {
    const cert = (await certificateNamed(page, certName))!;
    const host = await page.request.post(`${API}/proxy-hosts`, {
      data: { name: `Shop ${stamp}`, domains: [certDomain], upstreams: ['127.0.0.1:8080'], certificateId: cert.id },
      headers: HEADERS,
    });
    expect(host.status(), await host.text()).toBe(201);
    cleanup.hosts.push((await host.json()).id as number);

    await expect.poll(() => liveProviderFor(certDomain), POLL).toBe('godaddy');
    await expect.poll(() => liveProviderFor(plainDomain), POLL).toBe('cloudflare');
  });

  test('editing the certificate back to the default provider, then to GoDaddy again, reaches Caddy', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('button', { name: `More actions for ${certName}` }).click();
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    const sheet = page.getByRole('dialog', { name: 'Edit certificate' });
    await expect(sheet.getByLabel('Name', { exact: true })).toHaveValue(certName);
    await expect(sheet.getByLabel('Domains (one per line)')).toHaveValue(certDomain);
    await expect(sheet.getByLabel('DNS provider')).toHaveValue('godaddy');

    await sheet.getByLabel('DNS provider').selectOption({ label: 'Default (Cloudflare)' });
    await sheet.getByRole('button', { name: 'Save changes' }).click();
    await expect(sheet).toBeHidden();
    expect((await certificateNamed(page, certName))!.providerOptions).toBeNull();
    await expect.poll(() => liveProviderFor(certDomain), POLL).toBe('cloudflare');

    await page.getByRole('button', { name: `More actions for ${certName}` }).click();
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    const again = page.getByRole('dialog', { name: 'Edit certificate' });
    await expect(again.getByLabel('DNS provider')).toHaveValue('');
    await again.getByLabel('DNS provider').selectOption({ label: 'GoDaddy' });
    await again.getByRole('button', { name: 'Save changes' }).click();
    await expect(again).toBeHidden();
    await expect.poll(() => liveProviderFor(certDomain), POLL).toBe('godaddy');
  });

  test('a new host picks GoDaddy in its Certificate section and saves with it', async ({ page }) => {
    await openNewHost(page);
    await fillHostBasics(page, { name: `Editor ${stamp}`, domain: hostDomain, upstream: '127.0.0.1:8080' });
    await openEditorSection(page, 'Certificate');

    // Automatic TLS: the effective provider is named before anything is saved.
    await expect(page.getByTestId('certificate-challenge')).toHaveText('DNS-01 with Cloudflare (default)');
    await page.getByRole('button', { name: 'Use a different DNS provider' }).click();

    const sheet = page.getByRole('dialog', { name: 'New managed certificate' });
    await expect(sheet.getByLabel('Name', { exact: true })).toHaveValue(hostDomain);
    await expect(sheet.getByLabel('Domains (one per line)')).toHaveValue(hostDomain);
    await expect(sheet.getByLabel('DNS provider')).toHaveValue('godaddy');
    await sheet.getByRole('button', { name: 'Create certificate' }).click();
    await expect(sheet).toBeHidden();

    // The new certificate is chosen, and the effective provider changed with it.
    await expect(page.getByRole('combobox', { name: 'Certificate', exact: true })).not.toHaveValue('');
    await expect(page.getByTestId('certificate-challenge')).toHaveText('DNS-01 with GoDaddy');
    const hostId = await saveHostEditor(page);
    cleanup.hosts.push(hostId!);

    const cert = await certificateNamed(page, hostDomain);
    expect(cert, 'the certificate made from the host editor').toBeDefined();
    cleanup.certs.push(cert!.id);
    expect(cert!.providerOptions).toEqual({ provider: 'godaddy' });
    const host = (await (await page.request.get(`${API}/proxy-hosts/${hostId}`)).json()) as { certificateId: number | null };
    expect(host.certificateId).toBe(cert!.id);

    await expect.poll(() => liveProviderFor(hostDomain), POLL).toBe('godaddy');
    // The other hosts did not move.
    expect(liveProviderFor(plainDomain)).toBe('cloudflare');
  });

  test('the saved host shows GoDaddy as its provider, and the certificate can be edited from there', async ({ page }) => {
    const hosts = (await (await page.request.get(`${API}/proxy-hosts`)).json()) as { id: number; name: string }[];
    const host = hosts.find((candidate) => candidate.name === `Editor ${stamp}`)!;
    await openHostEditor(page, host.id, 'Certificate');
    await expect(page.getByTestId('certificate-challenge')).toHaveText('DNS-01 with GoDaddy');

    await page.getByRole('button', { name: 'Edit certificate' }).click();
    const sheet = page.getByRole('dialog', { name: 'Edit certificate' });
    await expect(sheet.getByLabel('DNS provider')).toHaveValue('godaddy');
    await sheet.getByLabel('DNS provider').selectOption({ label: 'Default (Cloudflare)' });
    await sheet.getByRole('button', { name: 'Save changes' }).click();
    await expect(sheet).toBeHidden();
    await expect(page.getByTestId('certificate-challenge')).toHaveText('DNS-01 with Cloudflare (default)');
    expect((await certificateNamed(page, hostDomain))!.providerOptions).toBeNull();
    await expect.poll(() => liveProviderFor(hostDomain), POLL).toBe('cloudflare');
  });

  test('without a second provider the host editor does not offer one', async ({ page }) => {
    const res = await page.request.put(`${API}/settings/dns-provider`, {
      data: { providers: { cloudflare: { api_token: FAKE_CLOUDFLARE_TOKEN } }, default: 'cloudflare' },
      headers: HEADERS,
    });
    expect(res.ok(), await res.text()).toBeTruthy();
    await openNewHost(page);
    await openEditorSection(page, 'Certificate');
    await expect(page.getByTestId('certificate-challenge')).toHaveText('DNS-01 with Cloudflare (default)');
    await expect(page.getByRole('button', { name: 'Use a different DNS provider' })).toHaveCount(0);
  });
});
