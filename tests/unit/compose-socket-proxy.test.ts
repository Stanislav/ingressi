/**
 * On SELinux hosts the Docker socket proxy only reaches the socket with
 * labelling turned off for it; no other service of the stack gives up its
 * label.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/** Top-level services of docker-compose.yml and their lines (no YAML parser: the file is plain block style). */
function services(): Map<string, string> {
  const text = readFileSync(resolve(__dirname, '../../docker-compose.yml'), 'utf8');
  const lines = text.split('\n');
  const start = lines.indexOf('services:');
  const out = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const name = /^ {2}([a-z0-9-]+):\s*$/.exec(line)?.[1];
    if (name) {
      current = name;
      out.set(name, []);
    } else if (current) {
      out.get(current)!.push(line.replace(/\s+#.*$/, ''));
    }
  }
  return new Map([...out].map(([name, body]) => [name, body.join('\n')]));
}

describe('docker-compose.yml on SELinux hosts', () => {
  it('turns labelling off for the Docker socket proxy only', () => {
    const all = services();
    expect(all.get('docker-socket-proxy')).toMatch(/\n {4}security_opt:\n {6}- label=disable/);
    const others = [...all].filter(([name, body]) => name !== 'docker-socket-proxy' && body.includes('label=disable')).map(([name]) => name);
    expect(others).toEqual([]);
  });

  it('mounts the socket into no other service', () => {
    const withSocket = [...services()].filter(([, body]) => body.includes('/var/run/docker.sock')).map(([name]) => name);
    expect(withSocket).toEqual(['docker-socket-proxy']);
  });

  it('takes the engine socket from .env (Podman users have another path)', () => {
    // Docker's socket by default, the Podman socket (rootless:
    // /run/user/<uid>/podman/podman.sock) when ENGINE_SOCKET says so.
    expect(services().get('docker-socket-proxy')).toContain(
      '${ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro'
    );
  });

  it('lets Caddy bind the low ports on Podman, where a non-root user may not', () => {
    // Podman keeps net.ipv4.ip_unprivileged_port_start at 1024, so Caddy (which
    // runs as an unprivileged user) could not bind 80 and 443.
    expect(services().get('caddy')).toMatch(/\n {4}sysctls:\n {6}- net\.ipv4\.ip_unprivileged_port_start=0/);
  });
});
