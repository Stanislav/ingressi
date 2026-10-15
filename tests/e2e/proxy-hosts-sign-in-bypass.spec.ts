/**
 * The host editor and the addresses that skip sign-in (Access tab): the
 * field exists for the built-in sign-in, Authentik and generic forward auth
 * and not for client certificates; the list is saved normalized, shown in the
 * review with its undo, and filled again when the page is opened or the host
 * copied; a bad entry is shown next to the field before anything is saved;
 * and the warnings follow how Caddy reads the client address (Trusted
 * proxies). The traffic side is in functional/forward-auth-bypass-sources.spec.ts.
 */
import { test, expect, type Page } from '@playwright/test';
import { openEditorSection, openHostEditor, openNewHost, saveHostEditor, setEditorSwitch } from '../helpers/proxy-api';

const BASE = 'http://localhost:3000';
const API_PROXY_HOSTS = `${BASE}/api/v1/proxy-hosts`;
const API_TRUSTED_PROXIES = `${BASE}/api/v1/settings/trusted-proxies`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE };

const WARNING_PRIVATE = /Matches the address that connects to Caddy/;
const WARNING_FORGEABLE = /lets a visitor forge the address/;

interface Provider {
  id: 'ingressi' | 'authentik' | 'generic';
  label: string;
  /** The field of the list in the editor. */
  field: string;
  /** The host field that holds the sign-in settings, and the field of the list in it. */
  section: 'ingressiForwardAuth' | 'authentik' | 'forwardAuth';
  key: 'bypass_sources' | 'bypassSources';
  /** The sign-in settings of a host at the start. */
  config: Record<string, unknown>;
}

const PROVIDERS: Provider[] = [
  { id: 'ingressi', label: 'Built-in sign-in', field: '#f-fi-sources', section: 'ingressiForwardAuth', key: 'bypass_sources', config: { enabled: true } },
  {
    id: 'authentik',
    label: 'Authentik',
    field: '#f-ak-sources',
    section: 'authentik',
    key: 'bypassSources',
    config: { enabled: true, outpostDomain: 'outpost.goauthentik.io', outpostUpstream: 'http://authentik:9000' },
  },
  {
    id: 'generic',
    label: 'Generic forward auth',
    field: '#f-fa-sources',
    section: 'forwardAuth',
    key: 'bypassSources',
    config: { enabled: true, provider: 'authelia', authUpstream: 'http://authelia:9091' },
  },
];

type ApiHost = Record<string, any> & { id: number };

async function createHost(page: Page, provider: Provider, extra: Record<string, unknown> = {}): Promise<ApiHost> {
  const response = await page.request.post(API_PROXY_HOSTS, {
    headers: HEADERS,
    data: {
      name: `Bypass UI ${provider.id}`,
      domains: [`bypass-ui-${provider.id}.local`],
      upstreams: ['localhost:9990'],
      sslForced: false,
      [provider.section]: provider.config,
      ...extra,
    },
  });
  expect(response.ok(), await response.text()).toBeTruthy();
  return (await response.json()) as ApiHost;
}

async function getHost(page: Page, id: number): Promise<ApiHost> {
  return (await (await page.request.get(`${API_PROXY_HOSTS}/${id}`)).json()) as ApiHost;
}

async function deleteHost(page: Page, id: number): Promise<void> {
  await page.request.delete(`${API_PROXY_HOSTS}/${id}`, { headers: { Origin: BASE } }).catch(() => undefined);
}

const sourcesOf = (host: ApiHost, provider: Provider): string[] => (host[provider.section]?.[provider.key] as string[] | undefined) ?? [];

/**
 * Opens the editor of a host afresh. A visit to the address the page already
 * has (only the hash is the same) keeps what the page loaded, so it goes
 * through the list first.
 */
async function reopen(page: Page, hostId: number, section: 'Access'): Promise<void> {
  await page.goto('/proxy-hosts');
  await openHostEditor(page, hostId, section);
}

/** Gives a host a list through the API. */
async function setSources(page: Page, host: ApiHost, provider: Provider, sources: string[]): Promise<void> {
  const response = await page.request.put(`${API_PROXY_HOSTS}/${host.id}`, {
    headers: HEADERS,
    data: { [provider.section]: { ...provider.config, [provider.key]: sources } },
  });
  expect(response.ok(), await response.text()).toBeTruthy();
}

test.describe('Skip sign-in from (host editor)', () => {
  for (const provider of PROVIDERS) {
    test.describe(provider.label, () => {
      test('saves the list normalized, shows it in the review and fills the field again', async ({ page }) => {
        const host = await createHost(page, provider);
        try {
          await openHostEditor(page, host.id, 'Access');
          const field = page.locator(provider.field);
          await expect(field).toBeVisible();
          await expect(field).toHaveValue('');
          await expect(page.getByText('Skip sign-in from, optional')).toBeVisible();

          await field.fill('192.168.1.77/24, 10.0.0.5\n2001:DB8::/32  192.168.1.0/24');
          await page.getByTestId('host-editor-bar').getByRole('button', { name: 'Review changes' }).click();
          const review = page.getByRole('region', { name: /^Review / });
          await expect(review).toBeVisible();
          await expect(review.getByText('Skip sign-in from: 192.168.1.77/24, 10.0.0.5, 2001:DB8::/32, 192.168.1.0/24')).toBeVisible();
          await review.getByRole('button', { name: /^(Save changes)$/ }).click();
          await expect(page.getByTestId('host-editor-bar').getByText('Saved', { exact: true })).toBeVisible({ timeout: 15_000 });

          expect(sourcesOf(await getHost(page, host.id), provider)).toEqual(['192.168.1.0/24', '10.0.0.5', '2001:db8::/32']);

          await reopen(page, host.id, 'Access');
          await expect(page.locator(provider.field)).toHaveValue('192.168.1.0/24, 10.0.0.5, 2001:db8::/32');
        } finally {
          await deleteHost(page, host.id);
        }
      });

      test('clearing the field removes the list', async ({ page }) => {
        const host = await createHost(page, provider);
        try {
          await setSources(page, host, provider, ['192.168.1.0/24']);
          await openHostEditor(page, host.id, 'Access');
          await expect(page.locator(provider.field)).toHaveValue('192.168.1.0/24');
          await page.locator(provider.field).fill('');
          await saveHostEditor(page);
          expect(sourcesOf(await getHost(page, host.id), provider)).toEqual([]);
        } finally {
          await deleteHost(page, host.id);
        }
      });

      test('a change can be undone from the review', async ({ page }) => {
        const host = await createHost(page, provider);
        try {
          await openHostEditor(page, host.id, 'Access');
          await page.locator(provider.field).fill('10.0.0.0/8');
          const bar = page.getByTestId('host-editor-bar');
          await expect(bar).toContainText('1 unsaved change');
          await bar.getByRole('button', { name: 'Review changes' }).click();
          const review = page.getByRole('region', { name: /^Review / });
          await expect(review.getByText('Skip sign-in from: 10.0.0.0/8')).toBeVisible();
          await review.getByRole('button', { name: /^Undo/ }).first().click();
          await expect(page.locator(provider.field)).toHaveValue('');
          expect(sourcesOf(await getHost(page, host.id), provider)).toEqual([]);
        } finally {
          await deleteHost(page, host.id);
        }
      });

      test('shows a bad entry next to the field and does not open the review', async ({ page }) => {
        const host = await createHost(page, provider);
        try {
          await openHostEditor(page, host.id, 'Access');
          const field = page.locator(provider.field);

          await field.fill('192.168.1.0/24, office.example.com');
          await page.getByTestId('host-editor-bar').getByRole('button', { name: 'Save', exact: true }).click();
          await expect(page.getByText('"office.example.com" is not an IP address, a CIDR range or private_ranges')).toBeVisible();
          await expect(field).toHaveAttribute('aria-invalid', 'true');
          await expect(page.getByRole('region', { name: /^Review / })).toHaveCount(0);
          await expect(page.getByRole('tab', { name: /^Access/ })).toContainText(/problem/);

          await field.fill('0.0.0.0/0');
          await expect(page.getByText(/matches every address/)).toBeVisible();
          await field.fill('10.0.0.0/33');
          await expect(page.getByText(/"10\.0\.0\.0\/33" is not an IP address/)).toBeVisible();

          // Fixed, it goes through.
          await field.fill('192.168.1.0/24');
          await expect(page.getByText(/is not an IP address|matches every address/)).toHaveCount(0);
          await saveHostEditor(page);
          expect(sourcesOf(await getHost(page, host.id), provider)).toEqual(['192.168.1.0/24']);
        } finally {
          await deleteHost(page, host.id);
        }
      });

      test('a copy of the host starts with the same list', async ({ page }) => {
        const host = await createHost(page, provider);
        try {
          await setSources(page, host, provider, ['203.0.113.9', '192.168.1.0/24']);
          await openNewHost(page, `?from=${host.id}`);
          await openEditorSection(page, 'Access');
          await expect(page.locator(provider.field)).toHaveValue('203.0.113.9, 192.168.1.0/24');
        } finally {
          await deleteHost(page, host.id);
        }
      });
    });
  }

  test('a new host can be created with the list', async ({ page }) => {
    await openNewHost(page);
    await page.getByLabel('Name', { exact: true }).fill('Bypass UI new host');
    await page.getByLabel('Add domains').fill('bypass-ui-new.local');
    await page.getByLabel('Add domains').press('Enter');
    await page.getByPlaceholder('10.0.0.5:8080').first().fill('localhost:9991');
    await openEditorSection(page, 'Access');
    await page.getByRole('group', { name: 'Provider' }).getByRole('button', { name: /sign-in$/ }).click();
    await page.locator('#f-fi-sources').fill('192.168.1.0/24');
    const id = await saveHostEditor(page);
    try {
      expect(id).toBeGreaterThan(0);
      const host = await getHost(page, id!);
      expect(host.ingressiForwardAuth).toMatchObject({ enabled: true, bypass_sources: ['192.168.1.0/24'] });
    } finally {
      if (id) await deleteHost(page, id);
    }
  });

  test('client certificates have no such field: they are not a sign-in', async ({ page }) => {
    const host = await createHost(page, PROVIDERS[0]);
    try {
      await openHostEditor(page, host.id, 'Access');
      await expect(page.locator('#f-fi-sources')).toBeVisible();
      await setEditorSwitch(page, 'Require client certificates', true);
      // The paths of the client certificates are there, the list of addresses only once, for the sign-in.
      await expect(page.locator('#f-mtls-paths-excluded')).toBeVisible();
      await expect(page.locator('[id$="-sources"]')).toHaveCount(1);
      await expect(page.getByText('Skip sign-in from, optional')).toHaveCount(1);
    } finally {
      await deleteHost(page, host.id);
    }
  });

  test('the field is not there while no sign-in is chosen', async ({ page }) => {
    const host = await createHost(page, PROVIDERS[0], { ingressiForwardAuth: null });
    try {
      await openHostEditor(page, host.id, 'Access');
      await expect(page.locator('[id$="-sources"]')).toHaveCount(0);
      await page.getByRole('group', { name: 'Provider' }).getByRole('button', { name: 'Authentik' }).click();
      await expect(page.locator('#f-ak-sources')).toBeVisible();
      await page.getByRole('group', { name: 'Provider' }).getByRole('button', { name: 'None' }).click();
      await expect(page.locator('[id$="-sources"]')).toHaveCount(0);
    } finally {
      await deleteHost(page, host.id);
    }
  });

  test.describe('warnings about the client address', () => {
    let original: Record<string, unknown> = { ranges: [] };

    test.beforeAll(async ({ browser }) => {
      const page = await browser.newPage();
      const response = await page.request.get(API_TRUSTED_PROXIES);
      // Unset, the settings read as nothing: put back as an empty list, which is what the route accepts.
      if (response.ok()) original = { ranges: [], ...(((await response.json()) as Record<string, unknown> | null) ?? {}) };
      await page.close();
    });

    test.afterAll(async ({ browser }) => {
      const page = await browser.newPage();
      const restored = await page.request.put(API_TRUSTED_PROXIES, { headers: HEADERS, data: original });
      expect(restored.ok(), await restored.text()).toBe(true);
      await page.close();
    });

    const setTrusted = async (page: Page, settings: Record<string, unknown>) => {
      const response = await page.request.put(API_TRUSTED_PROXIES, { headers: HEADERS, data: settings });
      expect(response.ok(), await response.text()).toBeTruthy();
    };

    test('private networks warn while no proxy is trusted, public ones and an empty field do not', async ({ page }) => {
      await setTrusted(page, { ranges: [] });
      const host = await createHost(page, PROVIDERS[1]);
      try {
        await openHostEditor(page, host.id, 'Access');
        const field = page.locator('#f-ak-sources');
        await expect(page.getByText(WARNING_PRIVATE)).toHaveCount(0);

        await field.fill('192.168.1.0/24');
        await expect(page.getByText(WARNING_PRIVATE)).toBeVisible();
        await field.fill('private_ranges');
        await expect(page.getByText(WARNING_PRIVATE)).toBeVisible();
        await field.fill('203.0.113.0/24, 2001:db8::/32');
        await expect(page.getByText(WARNING_PRIVATE)).toHaveCount(0);
        await field.fill('203.0.113.9, 10.0.0.5');
        await expect(page.getByText(WARNING_PRIVATE)).toBeVisible();
        await field.fill('');
        await expect(page.getByText(WARNING_PRIVATE)).toHaveCount(0);
      } finally {
        await deleteHost(page, host.id);
      }
    });

    test('a trusted proxy that X-Forwarded-For is read from the loose way warns about forging', async ({ page }) => {
      await setTrusted(page, { ranges: ['172.18.0.0/16'] });
      const host = await createHost(page, PROVIDERS[2]);
      try {
        await openHostEditor(page, host.id, 'Access');
        const field = page.locator('#f-fa-sources');
        await field.fill('203.0.113.9');
        await expect(page.getByText(WARNING_FORGEABLE)).toBeVisible();
        // The private-network warning is about the address of the connection: with proxies trusted it does not apply.
        await field.fill('private_ranges');
        await expect(page.getByText(WARNING_FORGEABLE)).toBeVisible();
        await expect(page.getByText(WARNING_PRIVATE)).toHaveCount(0);
        await field.fill('');
        await expect(page.getByText(WARNING_FORGEABLE)).toHaveCount(0);
      } finally {
        await deleteHost(page, host.id);
      }
    });

    test('strict parsing, or a header the proxy sets itself, takes the warning away', async ({ page }) => {
      const host = await createHost(page, PROVIDERS[0]);
      try {
        for (const settings of [
          { ranges: ['172.18.0.0/16'], strict: true },
          { ranges: ['172.18.0.0/16'], client_ip_headers: ['Cf-Connecting-Ip'] },
        ]) {
          await setTrusted(page, settings);
          await reopen(page, host.id, 'Access');
          await page.locator('#f-fi-sources').fill('private_ranges, 203.0.113.9');
          await expect(page.getByText(WARNING_FORGEABLE)).toHaveCount(0);
          await expect(page.getByText(WARNING_PRIVATE)).toHaveCount(0);
        }
        // Named, but X-Forwarded-For among them: loose again.
        await setTrusted(page, { ranges: ['172.18.0.0/16'], client_ip_headers: ['Cf-Connecting-Ip', 'X-Forwarded-For'] });
        await reopen(page, host.id, 'Access');
        await page.locator('#f-fi-sources').fill('203.0.113.9');
        await expect(page.getByText(WARNING_FORGEABLE)).toBeVisible();
      } finally {
        await deleteHost(page, host.id);
      }
    });
  });
});
