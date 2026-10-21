/**
 * SQL against a test stack's application database, whichever dialect it
 * runs on (tests/helpers/e2e-stack.ts).
 *
 * Specs seed what the UI cannot (a directory written straight into the
 * database, a user with a given status) or read back what the UI does not show. The
 * script runs inside the web container with Bun, against the database its
 * DATABASE_URL names: bun:sqlite for a file, Bun's PostgreSQL client for a
 * postgres:// URL. In the script, `db` is the same on both:
 *
 *   await db.all(sql, params)  rows
 *   await db.get(sql, params)  the first row, or null
 *   await db.run(sql, params)  nothing
 *   db.dialect                 "sqlite" or "postgres"
 *
 * Write SQL both dialects accept:
 *  - `?` placeholders (numbered for PostgreSQL here; never put a literal `?`
 *    in the SQL text, pass it as a parameter);
 *  - camelCase identifiers in double quotes ("userId"): PostgreSQL folds
 *    unquoted ones to lower case;
 *  - booleans as parameters (true/false), never 1 and 0 in the SQL text;
 *  - no SQLite-only functions or PRAGMAs; INSERT … ON CONFLICT (…) DO UPDATE
 *    SET x = excluded.x and RETURNING work on both.
 * Rows come back as JSON: booleans are 1/0 on SQLite and true/false on
 * PostgreSQL, so compare them with Boolean(…).
 */
import { execFileSync } from 'node:child_process';
import { execCmd } from './engine';

/** The main dashboard's container (replica A on the replicas stack). */
export const WEB_CONTAINER = 'ingressi-web';

const RESULT_MARKER = '__E2E_SQL_RESULT__';

const PRELUDE = `
const url = process.env.DATABASE_URL ?? "";
let db;
if (/^postgres(ql)?:\\/\\//i.test(url)) {
  const { SQL } = await import("bun");
  const client = new SQL({ url, max: 1 });
  const numbered = (text) => { let n = 0; return text.replace(/\\?/g, () => "$" + ++n); };
  const exec = (text, params = []) => client.unsafe(numbered(text), params);
  db = {
    dialect: "postgres",
    all: async (text, params) => [...(await exec(text, params))],
    get: async (text, params) => (await exec(text, params))[0] ?? null,
    run: async (text, params) => { await exec(text, params); },
    close: () => client.close(),
  };
} else {
  const { Database } = await import("bun:sqlite");
  const file = url.startsWith("file:") ? url.slice(5) : (process.env.DATABASE_PATH || "./data/ingressi.db");
  const client = new Database(file);
  client.run("PRAGMA busy_timeout = 5000");
  db = {
    dialect: "sqlite",
    all: async (text, params = []) => client.query(text).all(...params),
    get: async (text, params = []) => client.query(text).get(...params) ?? null,
    run: async (text, params = []) => { client.query(text).run(...params); },
    close: async () => client.close(),
  };
}
const emit = (value) => console.log(${JSON.stringify(RESULT_MARKER)} + JSON.stringify(value ?? null, (_key, v) => (typeof v === "bigint" ? Number(v) : v)));
`;

export type WebDbOptions = {
  /** The container to run in (default: the main dashboard). */
  container?: string;
  timeoutMs?: number;
};

/**
 * Runs `body` (JavaScript with top-level await, `db` and `emit(value)` in
 * scope) inside the web container and returns what it passed to `emit`
 * (null when it emits nothing). A failing statement fails the call.
 */
export function webDb<T = unknown>(body: string, options: WebDbOptions = {}): T {
  const script = `${PRELUDE}
try {
${body}
} finally {
  await db.close();
}
process.exit(0);
`;
  const output = execFileSync(execCmd(['-i', options.container ?? WEB_CONTAINER, 'bun', '-e', script]), {
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: options.timeoutMs ?? 60_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const line = output.split('\n').reverse().find((entry) => entry.startsWith(RESULT_MARKER));
  return (line ? JSON.parse(line.slice(RESULT_MARKER.length)) : null) as T;
}

/** One statement; returns its rows (none for a statement without RETURNING). */
export function webSql<T = Record<string, unknown>>(sql: string, params: unknown[] = [], options: WebDbOptions = {}): T[] {
  return webDb<T[]>(`emit(await db.all(${JSON.stringify(sql)}, ${JSON.stringify(params)}));`, options) ?? [];
}

/** Stores a setting row as `setSetting` would (the value is JSON). */
export function writeSettingRow(key: string, value: unknown, options: WebDbOptions = {}): void {
  webSql(
    'INSERT INTO settings (key, value, "updatedAt") VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, "updatedAt" = excluded."updatedAt"',
    [key, JSON.stringify(value), new Date().toISOString()],
    options
  );
}

/**
 * Creates or resets a local account with a password (bcrypt, as Better Auth
 * stores it) and its credential account row. Returns the user's id.
 */
export function ensureLocalUser(
  user: { username: string; password: string; role: string; email?: string },
  options: WebDbOptions = {}
): number {
  const email = user.email ?? `${user.username}@localhost`;
  return webDb<number>(`
    const email = ${JSON.stringify(email)};
    const username = ${JSON.stringify(user.username)};
    const role = ${JSON.stringify(user.role)};
    const hash = await Bun.password.hash(${JSON.stringify(user.password)}, { algorithm: "bcrypt", cost: 12 });
    const now = new Date().toISOString();
    let existing = await db.get("SELECT id FROM users WHERE email = ?", [email]);
    if (existing) {
      await db.run(
        'UPDATE users SET "passwordHash" = ?, role = ?, status = ?, "updatedAt" = ? WHERE email = ?',
        [hash, role, "active", now, email]
      );
    } else {
      await db.run(
        'INSERT INTO users (email, name, "passwordHash", role, provider, subject, username, status, "createdAt", "updatedAt") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [email, username, hash, role, "credentials", username, username, "active", now, now]
      );
      existing = await db.get("SELECT id FROM users WHERE email = ?", [email]);
    }
    const account = await db.get('SELECT id FROM accounts WHERE "userId" = ? AND "providerId" = ?', [existing.id, "credential"]);
    if (account) {
      await db.run('UPDATE accounts SET password = ?, "updatedAt" = ? WHERE id = ?', [hash, now, account.id]);
    } else {
      await db.run(
        'INSERT INTO accounts ("userId", issuer, "accountId", "providerId", password, "createdAt", "updatedAt") VALUES (?, ?, ?, ?, ?, ?, ?)',
        [existing.id, "local:credential", String(existing.id), "credential", hash, now, now]
      );
    }
    emit(existing.id);
  `, options);
}

/** Stores a Bearer API token for the user with `email`; returns the raw token. */
export function createApiTokenFor(email: string, name: string, options: WebDbOptions = {}): string {
  const token = `${name}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  webDb(`
    const { createHash } = await import("node:crypto");
    const user = await db.get("SELECT id FROM users WHERE email = ?", [${JSON.stringify(email)}]);
    if (!user) throw new Error("User not found: " + ${JSON.stringify(email)});
    const hash = createHash("sha256").update(${JSON.stringify(token)}).digest("hex");
    await db.run(
      'INSERT INTO api_tokens (name, "tokenHash", "createdBy", "createdAt") VALUES (?, ?, ?, ?)',
      [${JSON.stringify(name)}, hash, user.id, new Date().toISOString()]
    );
  `, options);
  return token;
}
