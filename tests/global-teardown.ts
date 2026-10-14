import { execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { composeArgs, composeEnv, keepStack } from './helpers/e2e-stack';

export default async function globalTeardown() {
  if (keepStack()) {
    console.log('[global-teardown] E2E_KEEP_STACK=1: leaving the Docker Compose test stack up.');
    return;
  }
  console.log('[global-teardown] Stopping Docker Compose test stack...');
  try {
    execFileSync('docker', [...composeArgs(), 'down', '-v', '--remove-orphans'], {
      stdio: 'inherit',
      cwd: process.cwd(),
      env: composeEnv(),
    });
  } catch (err) {
    console.warn('[global-teardown] docker compose down failed:', err);
  }

  const authDir = resolve(__dirname, '.auth');
  if (existsSync(authDir)) {
    rmSync(authDir, { recursive: true, force: true });
    console.log('[global-teardown] Removed', authDir);
  }

  console.log('[global-teardown] Done.');
}
