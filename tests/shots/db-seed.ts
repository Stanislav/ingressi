/**
 * What the screenshots need that the REST API does not set: how people
 * signed in (their identity providers, directories and SCIM), when, and
 * their second factors. Written straight into the test stack's SQLite
 * database through `docker compose exec web bun`, like the user helpers of
 * the e2e specs. The identity providers are stored turned off, so nothing
 * ever connects to them; they only give the accounts their labels.
 */
import { execFileSync } from 'node:child_process';
import { engineBin } from '../helpers/engine';

const COMPOSE_ARGS = ['compose', '-f', 'docker-compose.yml', '-f', 'tests/docker-compose.test.yml'];
const ENV = { ...process.env, CLICKHOUSE_PASSWORD: 'test-clickhouse-password-2026' };

export type SignInSource = 'password' | 'oidc' | 'saml' | 'ldap' | 'scim';

export type DbPerson = {
  email: string;
  /** Where the account signs in from; without "password" its password sign-in is removed. */
  sources: SignInSource[];
  /** Hours since the last dashboard sign-in; null: never (invited). */
  lastSignInHoursAgo: number | null;
  lastSignInMethod?: 'password' | 'sso' | 'saml' | 'ldap' | 'passkey';
  authenticatorApp?: boolean;
  passkeys?: number;
};

export type DbToken = { email: string; name: string; token: string; lastUsedHoursAgo: number };

/** Runs a Bun script in the web container with `data` as JSON in SEED_JSON; returns its standard output. */
export function runInWeb(script: string, data: unknown): string {
  return execFileSync(engineBin(), [...COMPOSE_ARGS, 'exec', '-T', '-e', `SEED_JSON=${JSON.stringify(data)}`, 'web', 'bun', '-e', script], {
    cwd: process.cwd(),
    env: ENV,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

const SCRIPT = String.raw`
import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "crypto";
const db = new Database("./data/ingressi.db");
db.run("PRAGMA busy_timeout = 10000");
const data = JSON.parse(process.env.SEED_JSON);
const now = Date.now();
const iso = (hoursAgo) => new Date(now - hoursAgo * 3600 * 1000).toISOString();
const created = iso(24 * 40);

function one(sql, ...args) { return db.query(sql).get(...args); }

// Identity providers, all turned off: they only label the accounts.
let oidc = one("SELECT id FROM oauth_providers WHERE name = ?", data.oidcName);
if (!oidc) {
  db.run("INSERT INTO oauth_providers (id, name, type, clientId, clientSecret, issuer, scopes, autoLink, enabled, source, createdAt, updatedAt) VALUES (?, ?, 'oidc', 'dashboard', 'unused', 'https://sso.example.com', 'openid email profile', 0, 0, 'ui', ?, ?)",
    ["corporate-sso", data.oidcName, created, created]);
  oidc = { id: "corporate-sso" };
}
let saml = one("SELECT id FROM saml_providers WHERE name = ?", data.samlName);
if (!saml) {
  db.run("INSERT INTO saml_providers (name, enabled, idpEntityId, idpSsoUrl, idpCertificates, emailAttribute, defaultRole, provisionUsers, linkExistingAccounts, createdAt, updatedAt) VALUES (?, 0, 'https://idp.example.org/saml', 'https://idp.example.org/saml/sso', '[]', 'email', 'viewer', 0, 0, ?, ?)",
    [data.samlName, created, created]);
  saml = one("SELECT id FROM saml_providers WHERE name = ?", data.samlName);
}
let ldap = one("SELECT id FROM ldap_directories WHERE name = ?", data.ldapName);
if (!ldap) {
  db.run("INSERT INTO ldap_directories (name, enabled, url, startTls, allowUnencrypted, bindDn, bindPassword, userSearchBase, userSearchFilter, createdAt, updatedAt) VALUES (?, 0, 'ldaps://dc1.corp.example.com', 0, 0, 'CN=svc-ingressi,OU=Service,DC=corp,DC=example,DC=com', 'unused', 'OU=People,DC=corp,DC=example,DC=com', '(sAMAccountName={username})', ?, ?)",
    [data.ldapName, created, created]);
  ldap = one("SELECT id FROM ldap_directories WHERE name = ?", data.ldapName);
}
const providerIds = { oidc: oidc.id, saml: "saml:" + saml.id, ldap: "ldap:" + ldap.id };

for (const person of data.people) {
  const user = one("SELECT id, username FROM users WHERE email = ?", person.email);
  if (!user) { console.log("missing user " + person.email); continue; }
  for (const kind of ["oidc", "saml", "ldap"]) {
    if (!person.sources.includes(kind)) continue;
    const providerId = providerIds[kind];
    if (!one("SELECT id FROM accounts WHERE userId = ? AND providerId = ?", user.id, providerId)) {
      db.run("INSERT INTO accounts (userId, issuer, accountId, providerId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)",
        [user.id, kind === "ldap" ? "local:" + providerId : "https://sso.example.com", person.email, providerId, created, created]);
    }
  }
  if (!person.sources.includes("password")) {
    db.run("DELETE FROM accounts WHERE userId = ? AND providerId = 'credential'", [user.id]);
    db.run("UPDATE users SET passwordHash = NULL WHERE id = ?", [user.id]);
  }
  if (person.sources.includes("scim") && !one("SELECT id FROM scim_users WHERE userId = ?", user.id)) {
    const name = person.email.split("@")[0];
    db.run("INSERT INTO scim_users (userId, userName, userNameKey, externalId, emails, active, origin, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, 1, 'scim', ?, ?)",
      [user.id, person.email, person.email.toLowerCase(), "ext-" + name, JSON.stringify([{ value: person.email, type: "work", primary: true }]), created, created]);
  }
  if (person.lastSignInHoursAgo !== null) {
    db.run("UPDATE users SET lastSignInAt = ?, lastSignInMethod = ? WHERE id = ?", [iso(person.lastSignInHoursAgo), person.lastSignInMethod ?? "password", user.id]);
  }
  if (person.authenticatorApp && !one("SELECT id FROM two_factors WHERE userId = ?", user.id)) {
    db.run("INSERT INTO two_factors (userId, secret, backupCodes, verified) VALUES (?, ?, ?, 1)", [user.id, "unused-" + randomBytes(8).toString("hex"), "unused"]);
    db.run("UPDATE users SET twoFactorEnabled = 1 WHERE id = ?", [user.id]);
  }
  const passkeys = person.passkeys ?? 0;
  const have = one("SELECT count(*) AS n FROM passkeys WHERE userId = ?", user.id).n;
  for (let i = have; i < passkeys; i++) {
    db.run("INSERT INTO passkeys (name, publicKey, userId, credentialID, counter, deviceType, backedUp, transports, createdAt) VALUES (?, ?, ?, ?, 0, 'multiDevice', 1, 'internal,hybrid', ?)",
      [i === 0 ? "Laptop" : "Phone", "unused", user.id, "shots-" + randomBytes(12).toString("hex"), created]);
  }
}

for (const signIn of data.providerSignIns) {
  const providerId = providerIds[signIn.kind];
  const user = one("SELECT id FROM users WHERE email = ?", signIn.email);
  db.run("INSERT OR REPLACE INTO sign_in_sources (providerId, lastSignInAt, lastUserId) VALUES (?, ?, ?)", [providerId, iso(signIn.hoursAgo), user ? user.id : null]);
}

for (const token of data.tokens) {
  const user = one("SELECT id FROM users WHERE email = ?", token.email);
  if (!user) continue;
  const hash = createHash("sha256").update(token.token).digest("hex");
  if (!one("SELECT id FROM api_tokens WHERE tokenHash = ?", hash)) {
    db.run("INSERT INTO api_tokens (name, tokenHash, createdBy, createdAt, lastUsedAt) VALUES (?, ?, ?, ?, ?)", [token.name, hash, user.id, created, iso(token.lastUsedHoursAgo)]);
  }
}
console.log("ok");
`;

export function seedIdentities(input: {
  oidcName: string;
  samlName: string;
  ldapName: string;
  people: DbPerson[];
  providerSignIns: { kind: 'oidc' | 'saml' | 'ldap'; email: string; hoursAgo: number }[];
  tokens: DbToken[];
}): string {
  return runInWeb(SCRIPT, input);
}

/** Sets an account's display name (the primary admin's is its user name on a fresh stack). */
export function setDisplayName(username: string, name: string): string {
  return runInWeb(
    String.raw`
import { Database } from "bun:sqlite";
const db = new Database("./data/ingressi.db");
db.run("PRAGMA busy_timeout = 10000");
const data = JSON.parse(process.env.SEED_JSON);
db.run("UPDATE users SET name = ? WHERE username = ?", [data.name, data.username]);
console.log("ok");
`,
    { username, name },
  );
}
