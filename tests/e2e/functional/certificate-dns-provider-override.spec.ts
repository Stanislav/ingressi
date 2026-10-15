/**
 * Functional test: per-certificate DNS provider override (#264, regression #336).
 *
 * A managed certificate can name its own DNS provider (`providerOptions.provider`)
 * instead of the global default. The override is stored as a JSON string, and the
 * Caddy config builder once read it without parsing it, so every certificate silently
 * used the default provider: the UI showed GoDaddy while the live Caddy TLS
 * automation policy still pointed at Cloudflare.
 *
 * Unit tests cover the builder; this spec pins the whole path from outside, reading
 * the policies Caddy is actually serving:
 *   API → database → applyCaddyConfig → Caddy admin API.
 */
import { test, expect, type Page } from '@playwright/test';
import { liveProviderFor } from '../../helpers/live-caddy';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
// The Cloudflare module checks the token's shape when Caddy provisions it (40 URL-safe characters).
const FAKE_CLOUDFLARE_TOKEN = `e2e${'0'.repeat(37)}`;

async function createManagedCertWithHost(
  page: Page,
  domain: string,
  providerOptions: { provider: string } | null,
): Promise<{ certId: number; hostId: number }> {
  const certRes = await page.request.post(`${API}/certificates`, {
    data: {
      name: `DNS override ${domain}`,
      type: 'managed',
      domainNames: [domain],
      autoRenew: true,
      ...(providerOptions ? { providerOptions } : {}),
    },
    headers: HEADERS,
  });
  expect(certRes.status(), await certRes.text()).toBe(201);
  const certId = (await certRes.json()).id as number;

  const hostRes = await page.request.post(`${API}/proxy-hosts`, {
    data: { name: `DNS override ${domain}`, domains: [domain], upstreams: ['127.0.0.1:8080'], certificateId: certId },
    headers: HEADERS,
  });
  expect(hostRes.status(), await hostRes.text()).toBe(201);
  return { certId, hostId: (await hostRes.json()).id as number };
}

test.describe.serial('Per-certificate DNS provider override', () => {
  const stamp = Date.now();
  const overrideDomain = `dns-override-${stamp}.example`;
  const defaultDomain = `dns-default-${stamp}.example`;
  const created: { certId: number; hostId: number }[] = [];

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

    created.push(await createManagedCertWithHost(page, overrideDomain, { provider: 'godaddy' }));
    created.push(await createManagedCertWithHost(page, defaultDomain, null));
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    for (const { certId, hostId } of created) {
      await page.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS });
      await page.request.delete(`${API}/certificates/${certId}`, { headers: HEADERS });
    }
    await page.request.put(`${API}/settings/dns-provider`, {
      data: { providers: {}, default: null },
      headers: HEADERS,
    });
    await page.close();
  });

  test('the certificate override beats the global default in the live Caddy config', async () => {
    await expect.poll(() => liveProviderFor(overrideDomain), { timeout: 30_000, intervals: [500, 1000, 2000] })
      .toBe('godaddy');
  });

  test('a certificate without an override keeps using the global default', async () => {
    await expect.poll(() => liveProviderFor(defaultDomain), { timeout: 30_000, intervals: [500, 1000, 2000] })
      .toBe('cloudflare');
  });

  test('the override survives a configuration re-apply', async ({ page }) => {
    const apply = await page.request.post(`${API}/caddy/apply`, { headers: HEADERS });
    expect(apply.ok(), await apply.text()).toBeTruthy();

    await expect.poll(() => liveProviderFor(overrideDomain), { timeout: 30_000, intervals: [500, 1000, 2000] })
      .toBe('godaddy');
    expect(liveProviderFor(defaultDomain)).toBe('cloudflare');
  });
});
