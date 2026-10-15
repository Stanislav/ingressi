/**
 * Regression: the Caddy file-writer's built-in rotation defaults silently
 * stopped compressing and cleaning up rolled log files in production,
 * filling the host disk (11GB+ of unrotated access/waf-rules logs). The fix
 * is to spell out roll settings explicitly instead of relying on upstream
 * defaults — these tests guard against that regressing silently again.
 */
import { describe, it, expect, vi } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import { buildCaddyDocument } from '../../src/lib/caddy';
import { saveLoggingSettings } from '../../src/lib/settings';

const ROLL_FIELDS = {
  roll: true,
  roll_size_mb: 100,
  roll_gzip: true,
  roll_keep: 10,
  roll_keep_days: 30,
};

function loggingLogs(doc: unknown): Record<string, { writer?: Record<string, unknown> }> {
  return (doc as { logging?: { logs?: Record<string, { writer?: Record<string, unknown> }> } })
    ?.logging?.logs ?? {};
}

describe('Caddy log writer rotation settings', () => {
  it('waf_rules writer always carries explicit roll settings (unconditional logger)', async () => {
    const doc = await buildCaddyDocument();
    const writer = loggingLogs(doc).waf_rules?.writer;
    expect(writer).toMatchObject(ROLL_FIELDS);
  });

  it('http_access writer carries explicit roll settings when access logging is enabled', async () => {
    await saveLoggingSettings({ enabled: true, format: 'json' });
    const doc = await buildCaddyDocument();
    const writer = loggingLogs(doc).http_access?.writer;
    expect(writer).toMatchObject(ROLL_FIELDS);
  });

  it('tls_issuance writes the certificate loggers\' errors to its own small rolled file, leaving Caddy\'s output alone', async () => {
    const doc = await buildCaddyDocument();
    const log = (doc as { logging: { logs: Record<string, Record<string, unknown>> } }).logging.logs.tls_issuance;
    expect(log.writer).toMatchObject({ output: 'file', filename: '/logs/tls-issuance.log', mode: '0640', roll: true, roll_gzip: true, roll_size_mb: 10, roll_keep: 3, roll_keep_days: 30 });
    expect(log.include).toEqual(['tls.obtain', 'tls.renew', 'tls.issuance.acme']);
    expect(log.level).toBe('ERROR');
    expect(log.encoder).toEqual({ format: 'json' });
    // No "default" log is defined: Caddy keeps printing these loggers itself.
    expect(Object.keys((doc as { logging: { logs: object } }).logging.logs)).not.toContain('default');
  });

  it('does not omit any roll field (would silently fall back to Caddy defaults)', async () => {
    const doc = await buildCaddyDocument();
    const writer = loggingLogs(doc).waf_rules?.writer as Record<string, unknown>;
    for (const field of Object.keys(ROLL_FIELDS)) {
      expect(writer[field], `writer.${field} must be explicitly set`).toBeDefined();
    }
  });
});
