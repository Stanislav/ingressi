/**
 * High availability, phase 3: shared request-path state
 * (ee/high-availability/shared-state) on the master of the test stack, with
 * the Valkey service of the certificate storage spec.
 *
 * The certificate storage's connection (backend local: Caddy is not
 * touched) and the shared state switch, with a generation the spec knows,
 * are written straight into the master's database; turning shared state off
 * goes through the API. The spec then signs in through the forward-auth portal and checks that
 * the redirect intent, the session and the exchange code are in Valkey, with
 * the TTLs of their lifetimes, and none of them in SQLite.
 */
import { test, expect, type Browser, type BrowserContext } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { engineBin } from '../helpers/engine';
import { randomBytes } from 'node:crypto';
import { webSql, writeSettingRow } from '../helpers/e2e-sql';

const MASTER = 'http://localhost:3002';
const API = `${MASTER}/api/v1`;
const DOMAIN = 'ha-shared-state-e2e.test';
const VALKEY_PASSWORD = 'e2e-valkey-password-2026';
const RUN = Date.now();
const PREFIX = `e2e-state-${RUN}`;
const GENERATION = randomBytes(6).toString('hex');
const NAMESPACE = `${PREFIX}:${GENERATION}:`;
const CONTAINERS = { valkey: 'ingressi-valkey', webMaster: 'ingressi-web-master' };
const json = { 'Content-Type': 'application/json', Origin: MASTER };

function engine(args: string[], options: { allowFailure?: boolean } = {}): string {
  try {
    return execFileSync(engineBin(), args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024, timeout: 60_000 });
  } catch (error) {
    if (options.allowFailure) return '';
    throw error;
  }
}

function valkey(...args: string[]): string {
  return engine(['exec', CONTAINERS.valkey, 'valkey-cli', '-a', VALKEY_PASSWORD, '--no-auth-warning', ...args]);
}

function namespaceKeys(): string[] {
  return valkey('--scan', '--pattern', `${NAMESPACE}*`).split('\n').map((line) => line.trim()).filter(Boolean);
}

/** Runs SQL against the master's database (SQLite on every stack); returns the rows. */
function masterSql(sql: string, params: unknown[] = []): unknown[] {
  return webSql(sql, params, { container: CONTAINERS.webMaster });
}

function writeSetting(key: string, value: unknown) {
  writeSettingRow(key, value, { container: CONTAINERS.webMaster });
}

async function loginContext(browser: Browser): Promise<BrowserContext> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${MASTER}/login`);
  await page.getByRole('textbox', { name: /username/i }).fill('testadmin');
  await page.getByRole('textbox', { name: /password/i }).fill('TestPassword2026!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 20_000 });
  await page.close();
  return context;
}

test.describe.serial('High availability: shared state (master + Valkey)', () => {
  test.describe.configure({ timeout: 120_000 });

  let admin: BrowserContext;
  let hostId: number | undefined;
  let previousStorage: string | null = null;

  test.beforeAll(async ({ browser }) => {
    admin = await loginContext(browser);
    expect(valkey('ping').trim()).toBe('PONG');
    const rows = masterSql("SELECT value FROM settings WHERE key = 'certificate_storage'") as Array<{ value: string }>;
    previousStorage = rows[0]?.value ?? null;
    writeSetting('certificate_storage', {
      backend: 'local',
      redis: {
        mode: 'standalone',
        addresses: ['valkey:6379'],
        db: 0,
        keyPrefix: `e2e-ha/state-${RUN}`,
        tls: { enabled: false, insecureSkipVerify: false },
        // Stored as given: decryptSecret passes values without the enc: prefix through.
        password: VALKEY_PASSWORD,
      },
    });
    writeSetting('ha_shared_state', { enabled: true, keyPrefix: PREFIX, generation: GENERATION });
  });

  test.afterAll(async () => {
    if (hostId !== undefined) await admin.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: json });
    await admin.request.delete(`${API}/high-availability/shared-state`, { headers: json });
    if (previousStorage === null) masterSql("DELETE FROM settings WHERE key = 'certificate_storage' RETURNING key");
    else writeSetting('certificate_storage', JSON.parse(previousStorage));
    for (const key of namespaceKeys()) valkey('DEL', key);
    await admin.close();
  });

  test('reports shared state on, reachable, with this node as the leader', async () => {
    // The setting is read again within a few seconds.
    await expect
      .poll(async () => (await (await admin.request.get(`${API}/high-availability/shared-state`)).json()).backend, { timeout: 15_000 })
      .toBe('redis');
    const view = await (await admin.request.get(`${API}/high-availability/shared-state`)).json();
    expect(view).toMatchObject({ enabled: true, keyPrefix: PREFIX, namespace: NAMESPACE, connection: { configured: true, addresses: ['valkey:6379'] } });
    expect(JSON.stringify(view)).not.toContain(VALKEY_PASSWORD);
    const status = await (await admin.request.get(`${API}/high-availability/shared-state/status`)).json();
    expect(status).toMatchObject({ backend: 'redis', reachable: true, leader: true });
  });

  test('keeps the portal sign-in in Valkey, with TTLs, and nothing in SQLite', async ({ browser }) => {
    const created = await admin.request.post(`${API}/proxy-hosts`, {
      headers: json,
      data: { name: 'HA shared state E2E', domains: [DOMAIN], upstreams: ['echo-server:8080'], sslForced: false, ingressiForwardAuth: { enabled: true } },
    });
    expect(created.status()).toBe(201);
    hostId = (await created.json()).id;
    expect((await admin.request.put(`${API}/proxy-hosts/${hostId}/forward-auth-access`, { headers: json, data: { userIds: [1], groupIds: [] } })).status()).toBe(200);
    const sessionsBefore = (masterSql('SELECT count(*) AS n FROM forward_auth_sessions') as Array<{ n: number }>)[0].n;

    const visitor = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      const page = await visitor.newPage();
      await page.goto(`${MASTER}/portal?rd=${encodeURIComponent(`http://${DOMAIN}/`)}`);
      await expect(page.getByLabel('Username')).toBeVisible({ timeout: 10_000 });

      const intents = namespaceKeys().filter((key) => key.includes('{fa}:i:'));
      expect(intents).toHaveLength(1);
      const intentTtl = Number(valkey('PTTL', intents[0]).trim());
      expect(intentTtl).toBeGreaterThan(0);
      expect(intentTtl).toBeLessThanOrEqual(600_000);

      await page.getByLabel('Username').fill('testadmin');
      await page.getByLabel('Password').fill('TestPassword2026!');
      // The portal follows redirectTo at once, so read the answer as it passes through, before the page navigates away.
      let answer: { status: number; body: { redirectTo?: string } } | null = null;
      await page.route('**/api/forward-auth/login', async (route) => {
        const response = await route.fetch();
        answer = { status: response.status(), body: await response.json() };
        await route.fulfill({ response });
      });
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await expect.poll(() => answer?.status, { timeout: 15_000 }).toBe(200);
      expect(answer!.body.redirectTo).toContain(`http://${DOMAIN}/.ingressi-auth/callback?code=`);
    } finally {
      await visitor.close();
    }

    const keys = namespaceKeys();
    // The intent was used once and is gone; a session (and its token key) and the exchange code are there.
    expect(keys.filter((key) => key.includes('{fa}:i:'))).toHaveLength(0);
    const session = keys.find((key) => /\{fa\}:s:\d+$/.test(key));
    const code = keys.find((key) => key.includes('{fa}:x:'));
    expect(session).toBeDefined();
    expect(code).toBeDefined();
    const sessionTtl = Number(valkey('PTTL', session!).trim());
    expect(sessionTtl).toBeGreaterThan(7 * 24 * 3600_000 - 120_000);
    expect(sessionTtl).toBeLessThanOrEqual(7 * 24 * 3600_000);
    const codeTtl = Number(valkey('PTTL', code!).trim());
    expect(codeTtl).toBeGreaterThan(0);
    expect(codeTtl).toBeLessThanOrEqual(60_000);
    for (const key of keys) expect(Number(valkey('PTTL', key).trim()), key).toBeGreaterThan(0);

    const sessionsAfter = (masterSql('SELECT count(*) AS n FROM forward_auth_sessions') as Array<{ n: number }>)[0].n;
    expect(sessionsAfter).toBe(sessionsBefore);

    // The session is listed through the API like one in SQLite.
    const listed = await (await admin.request.get(`${API}/forward-auth-sessions`)).json() as Array<{ proxyHostId: number }>;
    expect(listed.some((entry) => entry.proxyHostId === hostId)).toBe(true);
  });

  test('ends the host’s shared sessions when it is deleted', async () => {
    expect((await admin.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: json })).status()).toBeLessThan(300);
    hostId = undefined;
    expect(namespaceKeys().filter((key) => /\{fa\}:s:\d+$/.test(key))).toHaveLength(0);
  });

  test('turns off', async () => {
    const off = await admin.request.put(`${API}/high-availability/shared-state`, { headers: json, data: { enabled: false } });
    expect(off.status()).toBe(200);
    expect(await off.json()).toMatchObject({ enabled: false, backend: 'local' });
  });
});
