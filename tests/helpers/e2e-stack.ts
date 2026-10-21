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
 *
 * The run talks to Docker or to Podman (tests/helpers/engine.ts); the compose
 * files are the same for both.
 */
import { execFileSync } from 'node:child_process';
import { basename } from 'node:path';
import { engine, engineBin, engineCmd } from './engine';

export type E2eStack = 'sqlite' | 'postgres' | 'replicas';

export const E2E_STACK_ENV = 'E2E_STACK';

const BASE_FILES = ['docker-compose.yml', 'tests/docker-compose.test.yml'];

const STACK_FILES: Record<E2eStack, string[]> = {
  sqlite: BASE_FILES,
  postgres: [...BASE_FILES, 'tests/docker-compose.test.pg.yml'],
  replicas: [...BASE_FILES, 'tests/docker-compose.test.pg.yml', 'tests/docker-compose.test.replicas.yml'],
};

/**
 * The profiles the stack needs. They go on the command line, not into
 * COMPOSE_PROFILES: Podman's compose provider ignores that variable.
 */
const STACK_PROFILES: Record<E2eStack, string[]> = {
  sqlite: [],
  postgres: [],
  // The third replica (web-c) is in a profile of its own.
  replicas: ['third-replica'],
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
  const profiles = STACK_PROFILES[stack].flatMap((profile) => ['--profile', profile]);
  return ['compose', ...profiles, ...STACK_FILES[stack].flatMap((file) => ['-f', file])];
}

/** The whole argv of a compose command of the stack, engine included. */
export function composeCmd(args: string[], stack: E2eStack = e2eStack()): string[] {
  return [...engineCmd(composeArgs(stack)), ...args];
}

/**
 * The environment `docker compose` needs for the stack's interpolations
 * (the test override supplies the real values; see the e2e-worktree-needs-env note).
 */
export function composeEnv(stack: E2eStack = e2eStack()): NodeJS.ProcessEnv {
  return { ...process.env, CLICKHOUSE_PASSWORD: 'test-clickhouse-password-2026' };
}

/** A container of the stack, as the health spec sees it. */
export type ContainerInfo = {
  name: string;
  service: string;
  state: string;
  exitCode: number;
  health?: string;
};

/**
 * The compose project name: the directory the stack runs in, lowercased (the
 * default of both Docker Compose and Podman's compose provider).
 */
export function projectName(): string {
  const configured = process.env.COMPOSE_PROJECT_NAME?.trim();
  if (configured) return configured;
  return basename(process.cwd()).toLowerCase();
}

/**
 * Every container of the stack, running or not.
 *
 * Docker Compose lists them itself (`compose ps --format json`). Podman's
 * compose provider has no such format, so the containers are listed with
 * `podman ps` and filtered by the compose labels both engines set.
 */
export function listContainers(stack: E2eStack = e2eStack()): ContainerInfo[] {
  if (engine() === 'docker') {
    const output = execFileSync(engineBin(), [...composeArgs(stack), 'ps', '--format', 'json', '-a'], {
      cwd: process.cwd(),
      env: composeEnv(stack),
      encoding: 'utf-8',
    });

    // docker compose ps --format json outputs one JSON object per line
    return output
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const c = JSON.parse(line);
        return {
          name: c.Name ?? c.Service,
          service: c.Service ?? '',
          state: (c.State ?? '').toLowerCase(),
          exitCode: Number(c.ExitCode ?? 0),
          health: (c.Health ?? '').toLowerCase() || undefined,
        };
      });
  }

  const output = execFileSync(engineBin(), ['ps', '-a', '--format', 'json'], {
    cwd: process.cwd(),
    encoding: 'utf-8',
  });
  const containers = JSON.parse(output) as Array<{
    Names?: string[];
    State?: string;
    Status?: string;
    ExitCode?: number;
    Restarts?: number;
    Labels?: Record<string, string>;
  }>;

  return containers
    .filter((c) => c.Labels?.['com.docker.compose.project'] === projectName())
    .map((c) => ({
      name: c.Names?.[0] ?? '',
      service: c.Labels?.['com.docker.compose.service'] ?? '',
      state: (c.State ?? '').toLowerCase(),
      exitCode: Number(c.ExitCode ?? 0),
      // Podman puts the health in the status: "Up 2 minutes (healthy)".
      health: /\((healthy|unhealthy|starting)\)/.exec(c.Status ?? '')?.[1]?.toLowerCase(),
    }));
}

/**
 * Removes the containers the compose provider left behind.
 *
 * The L4 port manager recreates caddy through the Docker API, so the new
 * container carries Docker Compose's labels but not the ones Podman's compose
 * provider filters by: `podman compose down` leaves that one behind. Both
 * engines set com.docker.compose.project, so this finds it.
 */
export function removeLeftoverContainers(stack: E2eStack = e2eStack()): void {
  try {
    const ids = execFileSync(
      engineBin(),
      ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projectName()}`],
      { cwd: process.cwd(), encoding: 'utf-8' }
    )
      .trim()
      .split('\n')
      .filter(Boolean);
    if (ids.length === 0) return;
    execFileSync(engineBin(), ['rm', '-f', ...ids], { stdio: 'inherit', cwd: process.cwd() });
  } catch (err) {
    console.warn('[e2e] Removing the leftover containers failed:', err);
  }
}
