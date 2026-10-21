import { execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { composeArgs, composeEnv, removeLeftoverContainers } from './helpers/e2e-stack';
import { engineBin } from './helpers/engine';

export default async function globalTeardown() {
  console.log('[global-teardown] Stopping Docker Compose test stack...');
  try {
    execFileSync(engineBin(), [...composeArgs(), 'down', '-v', '--remove-orphans'], {
      stdio: 'inherit',
      cwd: process.cwd(),
      env: composeEnv(),
    });
  } catch (err) {
    console.warn('[global-teardown] docker compose down failed:', err);
  }
  removeLeftoverContainers();

  const authDir = resolve(__dirname, '.auth');
  if (existsSync(authDir)) {
    rmSync(authDir, { recursive: true, force: true });
    console.log('[global-teardown] Removed', authDir);
  }

  console.log('[global-teardown] Done.');
}
