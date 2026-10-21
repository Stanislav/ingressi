/**
 * E2E tests: LDAP / Active Directory sign-in (ee/ldap) against a real
 * OpenLDAP server (the openldap service in tests/docker-compose.test.yml,
 * seeded from tests/openldap/bootstrap.ldif).
 *
 * The directory is written straight into the database. It connects to
 * openldap:389 with StartTLS, trusting the CA the OpenLDAP image generated.
 * Everything the spec creates is removed afterwards, so the login page of
 * later specs is the usual one.
 */
import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { engineBin } from '../helpers/engine';
import { webDb, webSql } from '../helpers/e2e-sql';
import { composeArgs, composeEnv } from '../helpers/e2e-stack';

const BASE = 'http://localhost:3000';

const DIRECTORY_NAME = 'E2E OpenLDAP';
const USERS = {
  admin: { uid: 'e2e-admin', password: 'E2eAdminPassword2026!', email: 'e2e-admin@example.com' },
  user: { uid: 'e2e-user', password: 'E2eUserPassword2026!', email: 'e2e-user@example.com' },
  outsider: { uid: 'e2e-outsider', password: 'E2eOutsiderPassword2026!', email: 'e2e-outsider@example.com' },
};

function compose(args: string[], input?: string): string {
  return execFileSync(engineBin(), [...composeArgs(), ...args], {
    cwd: process.cwd(),
    env: composeEnv(),
    stdio: ['pipe', 'pipe', 'pipe'],
    input,
  }).toString();
}

/**
 * The CA certificate the OpenLDAP image generated for its StartTLS/LDAPS
 * listener (with --copy-service the image works on a copy under /container/run).
 */
function openLdapCa(): string {
  return compose([
    'exec', '-T', 'openldap', 'sh', '-c',
    'cat /container/run/service/slapd/assets/certs/ca.crt 2>/dev/null || cat /container/service/slapd/assets/certs/ca.crt',
  ]).trim();
}

/** Removes the directory, its account links and the users it created. */
function cleanUp(): void {
  webDb(`
    const emails = ${JSON.stringify(Object.values(USERS).map((user) => user.email))};
    for (const email of emails) {
      const user = await db.get("SELECT id FROM users WHERE email = ?", [email]);
      if (!user) continue;
      for (const table of ["sessions", "accounts", "two_factors"]) await db.run("DELETE FROM " + table + ' WHERE "userId" = ?', [user.id]);
      await db.run("DELETE FROM users WHERE id = ?", [user.id]);
    }
    for (const row of await db.all("SELECT id FROM ldap_directories WHERE name = ?", [${JSON.stringify(DIRECTORY_NAME)}])) {
      await db.run('DELETE FROM accounts WHERE "providerId" = ?', ["ldap:" + row.id]);
      await db.run("DELETE FROM ldap_directories WHERE id = ?", [row.id]);
    }
  `);
}

function createDirectory(caCertificate: string): number {
  const now = new Date().toISOString();
  const row = {
    name: DIRECTORY_NAME,
    enabled: true,
    url: 'ldap://openldap:389',
    startTls: true,
    allowUnencrypted: false,
    caCertificate,
    bindDn: 'cn=admin,dc=example,dc=com',
    // Stored as given: decryptSecret passes values without the enc: prefix through.
    bindPassword: 'ldap-admin-password-2026',
    userSearchBase: 'ou=people,dc=example,dc=com',
    userSearchFilter: '(&(objectClass=inetOrgPerson)(uid={username}))',
    usernameAttribute: 'uid',
    emailAttribute: 'mail',
    displayNameAttribute: 'cn',
    uniqueIdAttribute: 'entryUUID',
    groupMode: 'search',
    groupSearchBase: 'ou=groups,dc=example,dc=com',
    groupSearchFilter: '(&(objectClass=groupOfNames)(member={dn}))',
    groupRoleMappings: JSON.stringify([{ group: 'cn=ingressi-admins,ou=groups,dc=example,dc=com', role: 'admin' }]),
    defaultRole: 'user',
    requiredGroup: 'cn=ingressi-users,ou=groups,dc=example,dc=com',
    provisionUsers: true,
    linkExistingAccounts: false,
    allowWhenSsoEnforced: false,
    createdAt: now,
    updatedAt: now,
  };
  const columns = Object.keys(row);
  const [inserted] = webSql<{ id: number }>(
    `INSERT INTO ldap_directories (${columns.map((column) => `"${column}"`).join(', ')}) VALUES (${columns.map(() => '?').join(', ')}) RETURNING id`,
    columns.map((column) => row[column as keyof typeof row])
  );
  return Number(inserted.id);
}

/**
 * A client address of its own for each page, so the login limiter's
 * per-client counters of one run never block the next run.
 */
function clientAddress(): string {
  return `198.51.100.${1 + Math.floor(Math.random() * 254)}`;
}

async function signInWithDirectory(page: Page, uid: string, password: string): Promise<void> {
  await page.setExtraHTTPHeaders({ 'x-forwarded-for': clientAddress() });
  await page.goto(`${BASE}/login`);
  await expect(page.getByLabel('Sign in with')).toHaveValue(/^\d+$/);
  await page.getByLabel(`${DIRECTORY_NAME} username`).fill(uid);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

test.use({ storageState: { cookies: [], origins: [] } });

test.describe.serial('LDAP directory sign-in', () => {
  test.beforeAll(() => {
    cleanUp();
    createDirectory(openLdapCa());
  });

  test.afterAll(() => {
    cleanUp();
  });

  test('the login page offers the directory and keeps the local account one choice away', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    const select = page.getByLabel('Sign in with');
    await expect(select.locator('option')).toHaveText([DIRECTORY_NAME, 'Ingressi account']);
  });

  test('a member of the mapped admin group signs in and gets the admin role', async ({ page }) => {
    await signInWithDirectory(page, USERS.admin.uid, USERS.admin.password);
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 30_000 });
    const me = await page.request.get(`${BASE}/api/v1/mfa`);
    expect(me.status()).toBe(200);
    // Administrators see the Users page; it is in the sidebar.
    await expect(page.getByRole('link', { name: 'Users and groups', exact: true }).first()).toBeVisible();
  });

  test('a member of the required group only gets the default role', async ({ page }) => {
    await signInWithDirectory(page, USERS.user.uid, USERS.user.password);
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 30_000 });
    await expect(page.getByRole('link', { name: 'Users and groups', exact: true })).toHaveCount(0);
  });

  test('a wrong password, an unknown user and a user outside the required group get the same answer', async ({ page }) => {
    const attempts: Array<[string, string]> = [
      [USERS.user.uid, 'not-the-password'],
      ['nobody-here', 'not-the-password'],
      [USERS.outsider.uid, USERS.outsider.password],
    ];
    for (const [uid, password] of attempts) {
      await signInWithDirectory(page, uid, password);
      await expect(page.getByText('Invalid username or password')).toBeVisible({ timeout: 15_000 });
      await expect(page).toHaveURL(/\/login/);
    }
  });

  test('an empty password is refused like a wrong one', async ({ request }) => {
    const [{ id }] = webSql<{ id: number }>('SELECT id FROM ldap_directories WHERE name = ?', [DIRECTORY_NAME]);
    const response = await request.post(`${BASE}/api/auth/sign-in/ldap`, {
      headers: { origin: BASE, 'x-forwarded-for': clientAddress() },
      data: { directoryId: id, username: USERS.admin.uid, password: '' },
    });
    expect(response.status()).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'INVALID_USERNAME_OR_PASSWORD' });
  });
});
