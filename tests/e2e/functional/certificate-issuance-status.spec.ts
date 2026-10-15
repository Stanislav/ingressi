/**
 * Functional test: a host whose certificate Caddy never obtained (#338).
 *
 * A name no ACME server can issue for (".example") never gets a certificate, and
 * Caddy answers its TLS handshakes with "no certificate". The dashboard used to
 * read that as "not read yet" and showed "No issues" on the host. A host saved a
 * moment ago is still getting its first certificate; one that has had its
 * 15 minutes without is flagged on the proxy hosts list, the host's page and the
 * Certificates page.
 *
 * The host is aged by writing its last-saved time straight into the database,
 * since waiting for the real grace period would take 15 minutes.
 */
import { test, expect, type Page } from '@playwright/test';
import { findHostRow } from '../../helpers/proxy-api';
import { webSql } from '../../helpers/e2e-sql';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };

type OverviewRow = {
  id: string;
  kind: string;
  hostId: number | null;
  checkedAt: string | null;
  renewal: { state: string };
};

async function overviewRowOf(page: Page, hostId: number): Promise<OverviewRow | undefined> {
  const res = await page.request.get(`${API}/certificates/overview`);
  expect(res.ok()).toBeTruthy();
  const overview = (await res.json()) as { certificates: OverviewRow[] };
  return overview.certificates.find((row) => row.hostId === hostId);
}

test.describe.serial('Host without a certificate', () => {
  const stamp = Date.now();
  const name = `Never issued ${stamp}`;
  const domain = `never-${stamp}.example`;
  let hostId = 0;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const res = await page.request.post(`${API}/proxy-hosts`, {
      data: { name, domains: [domain], upstreams: ['127.0.0.1:8080'] },
      headers: HEADERS,
    });
    expect(res.status(), await res.text()).toBe(201);
    hostId = (await res.json()).id as number;
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    if (hostId) await page.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS }).catch(() => undefined);
    await page.close();
  });

  test('a host saved a moment ago is still getting its first certificate, and is not flagged', async ({ page }) => {
    await expect
      .poll(async () => (await overviewRowOf(page, hostId))?.renewal.state, { timeout: 60_000, intervals: [1000, 2000, 3000] })
      .toBe('pending');

    const row = await findHostRow(page, name);
    await expect(row.getByText('No issues', { exact: true })).toBeVisible();
    await expect(row.getByText('Obtaining')).toBeVisible();
    await expect(row.getByText('No certificate issued')).toHaveCount(0);
  });

  test('once it has had its grace period without one, the list, the host and the Certificates page say so', async ({ page }) => {
    const longAgo = new Date(Date.now() - 60 * 60_000).toISOString();
    webSql('UPDATE proxy_hosts SET "updatedAt" = ? WHERE id = ?', [longAgo, hostId]);

    await expect
      .poll(async () => (await overviewRowOf(page, hostId))?.renewal.state, { timeout: 60_000, intervals: [1000, 2000, 3000] })
      .toBe('missing');
    // When Caddy was last asked is part of the answer.
    expect((await overviewRowOf(page, hostId))!.checkedAt).not.toBeNull();

    // The proxy hosts list: no longer "No issues".
    const row = await findHostRow(page, name);
    await expect(row.getByText('No certificate issued')).toBeVisible();
    await expect(row.getByText('No issues', { exact: true })).toHaveCount(0);

    // The host's own page: the status, and what to check.
    await page.goto(`/proxy-hosts/${hostId}`);
    await expect(page.getByText('No certificate issued').first()).toBeVisible();
    await expect(page.getByText('Caddy has no certificate for this host.')).toBeVisible();

    // The Certificates page: not "Not read yet", and counted under "Needs attention".
    await page.goto('/certificates');
    const certificateRow = page.getByRole('row').filter({ hasText: domain });
    await expect(certificateRow.getByText('Not issued')).toBeVisible();
    await expect(certificateRow.getByText('No certificate')).toBeVisible();
    await expect(certificateRow.getByText('Not read yet')).toHaveCount(0);
    await page.getByRole('group', { name: 'Status' }).getByRole('button', { name: /needs attention/i }).click();
    await expect(certificateRow).toBeVisible();
  });
});
