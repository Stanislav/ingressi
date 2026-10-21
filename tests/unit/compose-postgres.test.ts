/**
 * docker-compose.postgres.yml (documentation/postgresql.md and
 * ee/docs/high-availability.md, "PostgreSQL replicas"): PostgreSQL 17 with
 * the C collation Ingressi requires, the web service on it, and a second
 * replica with its own data volume (its node id, src/lib/cluster-nodes.ts),
 * Caddy's logs read-write (whichever replica leads ingests and truncates
 * them) and the L4 ports files where the l4-port-manager looks.
 * `docker compose … config` validates the file itself; this pins what the
 * replicas depend on. No YAML parser: the files are plain block style, as in
 * compose-socket-proxy.test.ts.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_POOL_MAX } from '../../src/lib/db/postgres';

const ROOT = join(__dirname, '../..');

/** The top-level `section:` of a compose file, its entries and their lines without comments. */
function entries(file: string, section: string): Map<string, string> {
  const lines = readFileSync(join(ROOT, file), 'utf8').split('\n');
  const start = lines.indexOf(`${section}:`);
  expect(start, `${file} has ${section}:`).toBeGreaterThanOrEqual(0);
  const out = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const name = /^ {2}([a-z0-9-]+):\s*$/.exec(line)?.[1];
    if (name) {
      current = name;
      out.set(name, []);
    } else if (current && !/^\s*#/.test(line)) {
      out.get(current)!.push(line.replace(/\s+#.*$/, ''));
    }
  }
  return new Map([...out].map(([name, body]) => [name, `\n${body.join('\n')}`]));
}

const services = entries('docker-compose.postgres.yml', 'services');
const postgres = services.get('postgres')!;
const web2 = services.get('web-2')!;
const override = readFileSync(join(ROOT, 'docker-compose.postgres.yml'), 'utf8');

/** The volumes web-2 mounts. */
function web2Volumes(): string[] {
  const block = /\n {4}volumes: !override\n((?: {6}- .*\n?)+)/.exec(web2)?.[1] ?? '';
  return block.split('\n').map((line) => line.replace(/^ {6}- /, '').trim()).filter(Boolean);
}

describe('docker-compose.postgres.yml', () => {
  it('runs PostgreSQL 17 with the C collation, a health check and a volume, unpublished', () => {
    expect(postgres).toContain('\n    image: docker.io/library/postgres:17-alpine');
    expect(postgres).toContain('POSTGRES_INITDB_ARGS: --locale=C --encoding=UTF8');
    expect(postgres).toContain('POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?ERROR - POSTGRES_PASSWORD is required}');
    expect(postgres).toContain('pg_isready -U ingressi -d ingressi');
    expect(postgres).toContain('- postgres-data:/var/lib/postgresql/data');
    expect(postgres).not.toMatch(/\n {4}(ports|container_name):/);
  });

  it('allows enough connections for five replicas: the pool, 20 lock connections, the leader and the event connections each', () => {
    const maxConnections = Number(/max_connections=(\d+)/.exec(postgres)?.[1]);
    expect(maxConnections).toBeGreaterThanOrEqual(5 * (DEFAULT_POOL_MAX + 20 + 1 + 1));
  });

  it('points every replica at the database and at the same dashboard upstreams', () => {
    const shared = /\nx-postgres-environment: &postgres-environment\n((?: {2}.*\n|\s*\n)+)/.exec(override)?.[1] ?? '';
    expect(shared).toContain(
      'DATABASE_URL: postgres://ingressi:${POSTGRES_PASSWORD:?ERROR - POSTGRES_PASSWORD is required}@postgres:5432/ingressi?sslmode=disable'
    );
    expect(shared).toContain('DASHBOARD_UPSTREAMS: ${DASHBOARD_UPSTREAMS:-}');
    for (const name of ['web', 'web-2']) {
      const service = services.get(name)!;
      expect(service, name).toContain('<<: *postgres-environment');
      expect(service, name).toMatch(/\n {6}postgres:\n {8}condition: service_healthy/);
    }
  });

  it("gives web-2 its own data volume, Caddy's logs read-write, and no fixed name or published port", () => {
    expect(web2).toContain('profiles: [replicas]');
    expect(web2).toMatch(/\n {4}extends:\n {6}file: docker-compose\.yml\n {6}service: web/);
    expect(web2).toContain('container_name: !reset null');
    expect(web2).toContain('ports: !reset []');
    const volumes = web2Volumes();
    expect(volumes).toContain('web-2-data:/app/data');
    expect(volumes).toContain('caddy-logs:/logs');
    expect(volumes).toContain('acme-ca:/acme-ca');
    expect(volumes).toContain('geoip-data:/usr/share/GeoIP:ro,z');
    // The l4-port-manager watches web's data volume (docker-compose.yml).
    const l4Dir = /L4_PORTS_DIR: (\S+)/.exec(web2)?.[1];
    expect(volumes).toContain(`caddy-manager-data:${l4Dir}`);
    expect([...entries('docker-compose.postgres.yml', 'volumes').keys()]).toEqual(['postgres-data', 'web-2-data']);
    // web is up (and has joined) before web-2 starts.
    expect(web2).toMatch(/\n {6}web:\n {8}condition: service_healthy/);
  });

  it('keeps the base stack on SQLite, with the volumes the replicas share', () => {
    const base = entries('docker-compose.yml', 'services');
    expect(base.has('postgres')).toBe(false);
    const web = base.get('web')!;
    expect(web).toContain('DATABASE_URL: file:/app/data/ingressi.db');
    for (const volume of ['caddy-manager-data:/app/data', 'caddy-logs:/logs', 'acme-ca:/acme-ca']) {
      expect(web).toContain(`- ${volume}`);
    }
    expect(base.get('l4-port-manager')).toContain('- caddy-manager-data:/data');
  });
});
