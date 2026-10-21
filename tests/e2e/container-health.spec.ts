/**
 * E2E tests: Docker container health.
 *
 * Verifies that all containers in the test stack are running and healthy.
 * Catches issues like permission errors, missing dependencies, or
 * misconfigured Dockerfiles that cause sidecar containers to crash-loop.
 */
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { listContainers, e2eOnPostgres, type ContainerInfo } from '../helpers/e2e-stack';
import { engineBin } from '../helpers/engine';

/** Services that do one job at start-up and exit (openldap-certs makes the test LDAP certificates). */
const ONE_SHOT_SERVICES = new Set(['openldap-certs']);

function getContainers(): ContainerInfo[] {
  return listContainers();
}

test.describe('Container health', () => {
  let containers: ContainerInfo[];

  test.beforeAll(() => {
    containers = getContainers();
  });

  test('all containers are running', () => {
    expect(containers.length).toBeGreaterThan(0);
    for (const c of containers) {
      if (ONE_SHOT_SERVICES.has(c.service)) {
        expect(c.exitCode, `One-shot container "${c.name}" failed (exit code ${c.exitCode})`).toBe(0);
        continue;
      }
      expect(
        c.state,
        `Container "${c.name}" is not running (state: ${c.state})`
      ).toBe('running');
    }
  });

  test('web container is healthy', () => {
    const web = containers.find((c) => c.name.includes('web'));
    expect(web, 'web container not found').toBeTruthy();
    expect(web!.health, `web container health: ${web!.health}`).toBe('healthy');
  });

  test('caddy container is healthy', () => {
    const caddy = containers.find((c) => c.name.includes('caddy') && !c.name.includes('proxy-manager-web'));
    expect(caddy, 'caddy container not found').toBeTruthy();
    expect(caddy!.health, `caddy container health: ${caddy!.health}`).toBe('healthy');
  });

  test('clickhouse container is healthy', () => {
    const ch = containers.find((c) => c.name.includes('clickhouse'));
    test.skip(!ch, 'ClickHouse container not started (analytics disabled run)');
    expect(ch!.health, `clickhouse container health: ${ch!.health}`).toBe('healthy');
  });

  test('postgres container is healthy on the PostgreSQL stack', () => {
    test.skip(!e2eOnPostgres(), 'The dashboard runs on SQLite');
    const postgres = containers.find((c) => c.service === 'postgres');
    expect(postgres, 'postgres container not found').toBeTruthy();
    expect(postgres!.health, `postgres container health: ${postgres!.health}`).toBe('healthy');
  });

  test('l4-port-manager container is running (not crash-looping)', () => {
    const l4 = containers.find((c) => c.name.includes('l4-ports') || c.name.includes('l4-port-manager'));
    expect(l4, 'l4-port-manager container not found').toBeTruthy();
    expect(l4!.state, `l4-port-manager state: ${l4!.state}`).toBe('running');

    // Verify it hasn't restarted (restart count > 0 means crash-loop)
    const inspect = execFileSync(engineBin(), [
      'inspect', '--format', '{{.RestartCount}}', l4!.name,
    ], { encoding: 'utf-8' }).trim();
    const restartCount = Number(inspect);
    expect(
      restartCount,
      `l4-port-manager has restarted ${restartCount} time(s) — likely crash-looping`
    ).toBe(0);
  });
});
