/**
 * Global setup of tests/playwright.replicas.config.ts: PostgreSQL, Caddy and
 * two dashboard replicas (tests/docker-compose.test.replicas.yml), with
 * nothing else of the test stack. Replica A starts first (it migrates the
 * database), then replica B joins next to it.
 */
import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  ADMIN,
  REPLICA_A,
  REPLICA_B,
  REPLICAS,
  containerLogs,
  replicaCompose,
  soleLeader,
  waitForHealthy,
} from './helpers/replicas';
import { composeBuildFlags } from './helpers/e2e-stack';

const AUTH_DIR = resolve(__dirname, '.auth');
const AUTH_FILE = resolve(AUTH_DIR, 'admin.json');

/** What the replica specs need: the database, Caddy (and its upstream), ClickHouse for the leader's jobs. */
const BASE_SERVICES = ['postgres', 'caddy', 'clickhouse', 'echo-server'];

function log(message: string): void {
  console.log(`[global-setup-replicas] ${message}`);
}

async function seedAuthState(): Promise<void> {
  mkdirSync(AUTH_DIR, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage();
  try {
    await page.goto(`${REPLICA_A.url}/login`);
    await page.getByRole('textbox', { name: /username/i }).fill(ADMIN.username);
    await page.getByRole('textbox', { name: /password/i }).fill(ADMIN.password);
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 30_000 });
    await page.context().storageState({ path: AUTH_FILE });
  } finally {
    await browser.close();
  }
}

export default async function globalSetup() {
  const startedAt = new Date();
  log('Building and starting PostgreSQL, Caddy and replica A...');
  replicaCompose(['up', '-d', ...composeBuildFlags(), '--wait', '--wait-timeout', '240', ...BASE_SERVICES, REPLICA_A.service], { timeoutMs: 1_200_000 });
  await waitForHealthy(REPLICA_A);

  log('Starting replica B...');
  replicaCompose(['up', '-d', '--wait', '--wait-timeout', '240', REPLICA_B.service]);
  try {
    await Promise.all(REPLICAS.map((replica) => waitForHealthy(replica)));
    const leader = await soleLeader(REPLICAS, 60_000);
    log(`Both replicas serve; ${leader.nodeId} leads.`);
  } catch (error) {
    for (const replica of REPLICAS) {
      console.error(`[global-setup-replicas] ${replica.container} log:\n${containerLogs(replica.container, startedAt).split('\n').slice(-80).join('\n')}`);
    }
    throw error;
  }

  await seedAuthState();
  log('Done.');
}
