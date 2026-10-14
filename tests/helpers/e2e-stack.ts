/**
 * Which Docker Compose test stack the E2E run uses, and the compose
 * arguments that address it.
 *
 *  - sqlite: tests/playwright.config.ts (the default).
 *  - postgres: tests/playwright.pg.config.ts, the same stack with the
 *    dashboard on PostgreSQL (tests/docker-compose.test.pg.yml).
 *  - replicas: tests/playwright.replicas.config.ts, two dashboard replicas
 *    on one PostgreSQL (tests/docker-compose.test.replicas.yml).
 *
 * The Playwright config sets E2E_STACK; specs and the global set-up read it
 * here, so `docker compose` always sees the files the stack was started
 * with (a service started from fewer files would come back on SQLite).
 */
export type E2eStack = 'sqlite' | 'postgres' | 'replicas';

export const E2E_STACK_ENV = 'E2E_STACK';

const BASE_FILES = ['docker-compose.yml', 'tests/docker-compose.test.yml'];

const STACK_FILES: Record<E2eStack, string[]> = {
  sqlite: BASE_FILES,
  postgres: [...BASE_FILES, 'tests/docker-compose.test.pg.yml'],
  replicas: [...BASE_FILES, 'tests/docker-compose.test.pg.yml', 'tests/docker-compose.test.replicas.yml'],
};

export function e2eStack(): E2eStack {
  const value = process.env[E2E_STACK_ENV]?.trim() || 'sqlite';
  if (value === 'sqlite' || value === 'postgres' || value === 'replicas') return value;
  throw new Error(`${E2E_STACK_ENV} must be sqlite, postgres or replicas`);
}

/** Whether the dashboard of this run keeps its data in PostgreSQL. */
export function e2eOnPostgres(stack: E2eStack = e2eStack()): boolean {
  return stack !== 'sqlite';
}

/** `docker compose -f … -f …` for the stack (pass the result to execFileSync('docker', …)). */
export function composeArgs(stack: E2eStack = e2eStack()): string[] {
  return ['compose', ...STACK_FILES[stack].flatMap((file) => ['-f', file])];
}

/**
 * The environment `docker compose` needs for the stack's interpolations
 * (the test override supplies the real values; see the e2e-worktree-needs-env note).
 */
export function composeEnv(stack: E2eStack = e2eStack()): NodeJS.ProcessEnv {
  // The replicas stack's third node is in a profile of its own, so that
  // `up` never starts it unasked but `down` removes it.
  const profiles = stack === 'replicas' ? 'clickhouse,third-replica' : 'clickhouse';
  return { ...process.env, CLICKHOUSE_PASSWORD: 'test-clickhouse-password-2026', COMPOSE_PROFILES: profiles };
}

/**
 * `--build` for `docker compose up`, unless E2E_SKIP_BUILD=1: CI builds the
 * images once and loads them under the tags the compose files name
 * (.github/workflows/e2e.yml), so the stack must not build them again.
 */
export function composeBuildFlags(): string[] {
  return process.env.E2E_SKIP_BUILD === '1' ? [] : ['--build'];
}

/** True with E2E_KEEP_STACK=1: the teardown leaves the containers up, so CI can read their logs after a failure. */
export function keepStack(): boolean {
  return process.env.E2E_KEEP_STACK === '1';
}
