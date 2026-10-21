/**
 * The container engine the E2E run talks to: Docker (the default) or Podman.
 *
 * The stack is one compose file for both engines (docker-compose.yml): the
 * same services, the same images, the same behaviour. The command lines
 * differ, though: Podman has no `exec -T` (it allocates no TTY unless asked
 * for one) and its compose provider has no `ps --format json`. The helpers
 * here hide those differences, so the specs call `engineCmd(...)` instead of
 * `execFileSync('docker', ...)`.
 *
 * E2E_ENGINE=podman runs the suite against Podman. Without it, Docker is used
 * when it is installed and Podman otherwise.
 */
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';

export type Engine = 'docker' | 'podman';

export const ENGINE_ENV = 'E2E_ENGINE';

export function engine(): Engine {
  const value = (process.env[ENGINE_ENV] ?? '').trim().toLowerCase();
  if (value === 'docker' || value === 'podman') return value;
  return hasBinary('docker') ? 'docker' : 'podman';
}

export function hasBinary(name: string): boolean {
  return (process.env.PATH ?? '')
    .split(delimiter)
    .some((dir) => dir && existsSync(join(dir, name)));
}

/** The engine's command: `docker` or `podman`. */
export function engineBin(): string {
  return engine() === 'podman' ? 'podman' : 'docker';
}

/** The argv of an engine command: `engineCmd(['logs', 'x'])` → `['podman', 'logs', 'x']`. */
export function engineCmd(args: string[]): string[] {
  return [engineBin(), ...args];
}

/**
 * The arguments of `exec`. Podman has no `-T`: it allocates no TTY unless
 * `-t` is given, which is what `-T` asks Docker to do.
 */
export function execArgs(args: string[]): string[] {
  return engine() === 'podman' ? args.filter((arg) => arg !== '-T') : args;
}

/** The whole argv of `exec`: `execCmd(['-i', 'web'])` → `['podman', 'exec', '-i', 'web']`. */
export function execCmd(args: string[]): string[] {
  return engineCmd(['exec', ...execArgs(args)]);
}
