/**
 * Why Caddy has no certificate (src/lib/tls-issuance-log.ts): the error lines
 * of Caddy's tls-issuance.log, and what makes them fit to show. The lines
 * below are the ones Caddy wrote when Let's Encrypt refused a name; the
 * sanitizing cases are the ways an ACME or DNS provider error can carry
 * something that must not reach a page: URLs with keys in them, order and
 * account references, the stored DNS credentials, e-mail and IP addresses.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dns = vi.hoisted(() => ({ settings: null as null | { providers: Record<string, Record<string, string>>; default: string | null } }));
vi.mock('@/src/lib/settings', () => ({ getDnsProviderSettings: vi.fn(async () => dns.settings) }));

import { encryptSecret } from '@/src/lib/secret';
import {
  clearIssuanceCache,
  getIssuanceErrors,
  lastErrorsOf,
  parseIssuanceLine,
  sanitizeIssuanceMessage,
} from '@/src/lib/tls-issuance-log';

const TS = 1792072940.620099;
const entry = (extra: Record<string, unknown>) => JSON.stringify({ level: 'error', ts: TS, logger: 'tls.obtain', msg: 'could not get certificate from issuer', ...extra });

const REFUSED =
  'HTTP 400 urn:ietf:params:acme:error:rejectedIdentifier - Invalid identifiers requested :: Cannot issue for "x.example": Domain name does not end with a valid public suffix (TLD)';
const ZONE_ERROR =
  '[example.com] solving challenges: presenting for challenge: adding temporary record for zone "example.com.": expected 1 zone, got 0 for example.com. (order=https://acme-v02.api.letsencrypt.org/acme/order/1234567890/987654321) (ca=https://acme-v02.api.letsencrypt.org/directory)';

describe('parseIssuanceLine', () => {
  it('reads the identifier, time and error of a failed attempt', () => {
    expect(parseIssuanceLine(entry({ identifier: 'X.Example', issuer: 'acme-v02.api.letsencrypt.org-directory', error: REFUSED }))).toEqual({
      identifier: 'x.example',
      at: new Date(TS * 1000).toISOString(),
      error: REFUSED,
    });
  });

  it('takes the first of identifiers, and the renewal and ACME client loggers', () => {
    expect(parseIssuanceLine(entry({ logger: 'tls.renew', msg: 'renewing certificate', identifiers: ['*.example.com', 'example.com'], error: 'no' }))?.identifier).toBe('*.example.com');
    expect(parseIssuanceLine(entry({ logger: 'tls.issuance.acme.acme_client', identifier: 'a.example.com', error: 'no' }))?.identifier).toBe('a.example.com');
  });

  it('ignores everything else', () => {
    expect(parseIssuanceLine(entry({ level: 'info', identifier: 'a.example.com', error: 'x' }))).toBeNull();
    expect(parseIssuanceLine(entry({ logger: 'http.log.access', identifier: 'a.example.com', error: 'x' }))).toBeNull();
    expect(parseIssuanceLine(entry({ logger: 'tls.obtainer', identifier: 'a.example.com', error: 'x' }))).toBeNull();
    // Lock housekeeping names paths inside the container.
    expect(parseIssuanceLine(entry({ msg: 'unable to unlock', identifier: 'a.example.com', error: 'remove /data/caddy/locks/issue_cert_a.lock: no such file' }))).toBeNull();
    // The retry line has no identifier of its own.
    expect(parseIssuanceLine(entry({ msg: 'will retry', error: '[a.example.com] Obtain: boom', attempt: 1 }))).toBeNull();
    expect(parseIssuanceLine(entry({ identifier: 'a.example.com' }))).toBeNull();
    expect(parseIssuanceLine(entry({ identifier: 'a.example.com', error: 'x', ts: 'later' }))).toBeNull();
    expect(parseIssuanceLine('not json')).toBeNull();
    expect(parseIssuanceLine('[1,2]')).toBeNull();
    expect(parseIssuanceLine('')).toBeNull();
  });
});

describe('lastErrorsOf', () => {
  it('keeps the last error of each name', () => {
    const lines = [
      entry({ ts: 1, identifier: 'a.example.com', error: 'first' }),
      entry({ ts: 2, identifier: 'b.example.com', error: 'other' }),
      entry({ ts: 3, identifier: 'A.example.com', error: 'second' }),
    ];
    const result = lastErrorsOf(lines);
    expect(result.get('a.example.com')?.error).toBe('second');
    expect(result.get('b.example.com')?.error).toBe('other');
    expect(result.size).toBe(2);
  });
});

describe('sanitizeIssuanceMessage', () => {
  it('keeps the part that says what is wrong and drops the order and CA references', () => {
    expect(sanitizeIssuanceMessage(REFUSED)).toBe(REFUSED);
    expect(sanitizeIssuanceMessage(ZONE_ERROR)).toBe(
      '[example.com] solving challenges: presenting for challenge: adding temporary record for zone "example.com.": expected 1 zone, got 0 for example.com.'
    );
  });

  it('keeps what a DNS provider answered, as Caddy logged it for Cloudflare and GoDaddy', () => {
    const cloudflare =
      '[ingressi-probe-0001.com] solving challenges: presenting for challenge: adding temporary record for zone "com.": got error status: HTTP 403: [{Code:9109 Message:Invalid access token ErrorChain:[]}] (order=https://acme-staging-v02.api.letsencrypt.org/acme/order/353732093/51516744763) (ca=https://acme-staging-v02.api.letsencrypt.org/directory)';
    expect(sanitizeIssuanceMessage(cloudflare)).toBe(
      '[ingressi-probe-0001.com] solving challenges: presenting for challenge: adding temporary record for zone "com.": got error status: HTTP 403: [{Code:9109 Message:Invalid access token ErrorChain:[]}]'
    );
    // GoDaddy's error carries the challenge value it was asked to publish.
    const godaddy =
      '[*.ingressi-probe-0002.com] solving challenges: presenting for challenge: adding temporary record for zone "com.": could not append records: Domain: com; Record: _acme-challenge.ingressi-probe-0002, Status: 401; Body: ; PUT: [{"data":"09HDrDEjwMQ2GMIWjBywPAJBjw4t_vw0fP9cGz1l3ec","ttl":600}] (order=https://acme-staging-v02.api.letsencrypt.org/acme/order/353732093/51516745253) (ca=https://acme-staging-v02.api.letsencrypt.org/directory)';
    expect(sanitizeIssuanceMessage(godaddy)).toBe(
      '[*.ingressi-probe-0002.com] solving challenges: presenting for challenge: adding temporary record for zone "com.": could not append records: Domain: com; Record: _acme-challenge.ingressi-probe-0002, Status: 401; Body: ; PUT: [{"data":"[redacted]","ttl":600}]'
    );
    // A provider that does echo the credential it was given.
    expect(sanitizeIssuanceMessage('got error status: HTTP 403: bad token e2eSECRETtoken0123456789abcdefghijklmnop', ['e2eSECRETtoken0123456789abcdefghijklmnop'])).toBe(
      'got error status: HTTP 403: bad token [redacted]'
    );
  });

  it('cuts URLs down to scheme and host, so keys in the address are gone', () => {
    const text = 'Get "https://api.example.net/v1/zones?apikey=abcDEF123456789xyz&name=x.example": dial tcp 192.0.2.10:443: i/o timeout';
    const out = sanitizeIssuanceMessage(text);
    expect(out).toBe('Get "https://api.example.net": dial tcp [address]: i/o timeout');
    expect(out).not.toContain('apikey');
    expect(sanitizeIssuanceMessage('POST https://user:hunter2hunter2@dns.example.net:8443/path?token=1: 403')).toBe('POST https://dns.example.net: 403');
    // Brackets inside an address (an IPv6 host) do not end it early, leaving the path and key behind.
    expect(sanitizeIssuanceMessage('Get "https://[2001:db8::1]:8443/zones?key=K3Y123" failed')).toBe('Get "https://[address]" failed');
    expect(sanitizeIssuanceMessage('see (https://api.example.net/v1/x?token=T0K3N) and [https://api.example.net/y?k=1].')).toBe('see (https://api.example.net) and [https://api.example.net].');
    expect(sanitizeIssuanceMessage('creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429')).toBe(
      'creating new order: attempt 1: https://acme-v02.api.letsencrypt.org: HTTP 429'
    );
  });

  it('blanks out the stored credentials, also percent-encoded, but not short values', () => {
    const secrets = ['sk-live-abc/def+123', 'ab'];
    expect(sanitizeIssuanceMessage('auth failed for token sk-live-abc/def+123 on zone ab', secrets)).toBe('auth failed for token [redacted] on zone ab');
    expect(sanitizeIssuanceMessage('GET /zones?key=sk-live-abc%2Fdef%2B123 failed', secrets)).toBe('GET /zones?key=[redacted] failed');
    expect(sanitizeIssuanceMessage('SK-LIVE-ABC/DEF+123', secrets)).toBe('[redacted]');
  });

  it('replaces e-mail addresses and IP addresses', () => {
    expect(sanitizeIssuanceMessage('account for admin@example.com rejected')).toBe('account for [email] rejected');
    expect(sanitizeIssuanceMessage('lookup acme.example on 127.0.0.11:53: no such host')).toBe('lookup acme.example on [address]: no such host');
    expect(sanitizeIssuanceMessage('dial tcp [2001:db8::1]:443: connect: refused')).toBe('dial tcp [address]: connect: refused');
    expect(sanitizeIssuanceMessage('from 2001:db8::1 and fe80::1 and ::1 done')).toBe('from [address] and [address] and [address] done');
    // Times and ordinary text stay.
    expect(sanitizeIssuanceMessage('at 10:11:00 after 3 attempts')).toBe('at 10:11:00 after 3 attempts');
  });

  it('replaces keys and request IDs, but not long names', () => {
    expect(sanitizeIssuanceMessage('request 7f3a9c1e-4b2d-4e8a-9c6f-1a2b3c4d5e6f failed')).toBe('request [redacted] failed');
    expect(sanitizeIssuanceMessage('token e2e0000000000000000000000000000000000000 invalid')).toBe('token [redacted] invalid');
    const name = 'a-very-long-subdomain-without-digits.example.com';
    expect(sanitizeIssuanceMessage(`no zone for ${name}`)).toBe(`no zone for ${name}`);
  });

  it('drops control characters, so one error stays one line', () => {
    expect(sanitizeIssuanceMessage('first\nsecond\r\n\tthird\u0000\u001b[31m')).toBe('first second third [31m');
  });

  it('stays fast on a huge error, and still blanks out a credential deep inside it', () => {
    const secret = 'sk-live-0123456789abcdef';
    const huge = `${'a1'.repeat(200_000)} ${secret} ${'z9'.repeat(200_000)}`;
    const started = Date.now();
    const out = sanitizeIssuanceMessage(huge, [secret]);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(out.length).toBeLessThanOrEqual(300);
    expect(out).not.toContain(secret);
    expect(parseIssuanceLine(entry({ identifier: 'a.example.com', error: 'x'.repeat(150_000) }))).toBeNull();
  });

  it('cuts long text', () => {
    const out = sanitizeIssuanceMessage(`${'word '.repeat(200)}end`);
    expect(out.length).toBeLessThanOrEqual(300);
    expect(out.endsWith('…')).toBe(true);
  });
});

describe('sanitizeIssuanceMessage, over many shapes of error', () => {
  // A seeded generator, so a failure repeats: errors are built from the pieces real ones are made of.
  function random(seed: number) {
    let state = seed;
    return () => {
      state = (state * 1664525 + 1013904223) % 4294967296;
      return state / 4294967296;
    };
  }
  const SECRETS = ['sk-live-4f9a0c', 'p@ss/w0rd+key==', 'AbCdEf0123456789xyz', 'hunter2hunter2'];
  const pieces = [
    'presenting for challenge', 'adding temporary record for zone "example.com."', 'HTTP 403', 'Status: 401; Body: ', 'got error status', 'dial tcp', 'i/o timeout',
    '(order=https://acme.example.net/acme/order/1/2)', '(ca=https://acme.example.net/directory)', 'https://api.example.net/v1/zones?key=SECRET&x=1', 'http://user:SECRET@10.0.0.5:8443/p?token=SECRET',
    'contact admin@example.org please', 'mailto:ops@example.net', '203.0.113.7:443', '[2001:db8::7]:53', 'fe80::1', '7f3a9c1e-4b2d-4e8a-9c6f-1a2b3c4d5e6f',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlMTIzNDU2Nzg5MA', 'tok_' + 'a1'.repeat(20), 'line\nbreak\ttab\u0000nul\u009f', 'plain words only', '(TLD)', '::', ':'
  ];

  it('never lets a credential, a request address, an e-mail or an IP address through, and stays within the limits', () => {
    const next = random(20261015);
    for (let run = 0; run < 3000; run++) {
      const parts: string[] = [];
      const count = 1 + Math.floor(next() * 12);
      for (let i = 0; i < count; i++) {
        const piece = pieces[Math.floor(next() * pieces.length)];
        parts.push(piece.replace(/SECRET/g, SECRETS[Math.floor(next() * SECRETS.length)]));
        if (next() < 0.25) parts.push(SECRETS[Math.floor(next() * SECRETS.length)]);
      }
      const text = parts.join(next() < 0.5 ? ' ' : '');
      const out = sanitizeIssuanceMessage(text, SECRETS);
      for (const secret of SECRETS) expect(out.toLowerCase(), text).not.toContain(secret.toLowerCase());
      expect(out, text).not.toMatch(/https?:\/\/[^\s/]+[/?#]/i);
      expect(out, text).not.toMatch(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
      expect(out, text).not.toMatch(/[\w.+-]+@[\w-]+\.[a-z]{2,}/i);
      expect(out, text).not.toMatch(/[\p{Cc}]/u);
      expect(out.length, text).toBeLessThanOrEqual(300);
    }
  });
});

describe('getIssuanceErrors', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tls-issuance-'));
    file = join(dir, 'tls-issuance.log');
    dns.settings = null;
    clearIssuanceCache();
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('returns the sanitized last error of the names asked for, and nothing for others', async () => {
    writeFileSync(
      file,
      [
        entry({ ts: 100, identifier: 'old.example.com', error: 'older' }),
        entry({ ts: 200, identifier: 'example.com', error: ZONE_ERROR }),
        entry({ ts: 300, identifier: 'other.example.com', error: 'unrelated' }),
        '',
      ].join('\n')
    );
    const result = await getIssuanceErrors([' Example.COM ', 'none.example.com'], { file });
    expect([...result.keys()]).toEqual(['example.com']);
    expect(result.get('example.com')).toEqual({
      at: new Date(200_000).toISOString(),
      message: '[example.com] solving challenges: presenting for challenge: adding temporary record for zone "example.com.": expected 1 zone, got 0 for example.com.',
    });
  });

  it('blanks out the DNS provider credentials stored here', async () => {
    dns.settings = { default: 'godaddy', providers: { godaddy: { api_key: encryptSecret('key-VALUE-12345'), api_secret: 'plain-VALUE-67890' } } };
    writeFileSync(file, `${entry({ identifier: 'example.com', error: 'godaddy said key-VALUE-12345 and plain-VALUE-67890 are wrong' })}\n`);
    expect((await getIssuanceErrors(['example.com'], { file })).get('example.com')?.message).toBe('godaddy said [redacted] and [redacted] are wrong');
  });

  it('follows the file when Caddy logs another error', async () => {
    writeFileSync(file, `${entry({ ts: 1, identifier: 'a.example.com', error: 'first' })}\n`);
    expect((await getIssuanceErrors(['a.example.com'], { file })).get('a.example.com')?.message).toBe('first');
    appendFileSync(file, `${entry({ ts: 2, identifier: 'a.example.com', error: 'second' })}\n`);
    expect((await getIssuanceErrors(['a.example.com'], { file })).get('a.example.com')?.message).toBe('second');
  });

  it('reads only the end of a large file, without trusting the line it starts in', async () => {
    const filler = `${entry({ ts: 1, identifier: 'filler.example.com', error: 'x'.repeat(2000) })}\n`;
    const half = entry({ ts: 2, identifier: 'cut.example.com', error: 'whole' });
    writeFileSync(file, `${half}\n${filler.repeat(400)}${entry({ ts: 3, identifier: 'last.example.com', error: 'at the end' })}\n`);
    const result = await getIssuanceErrors(['cut.example.com', 'last.example.com'], { file });
    expect(result.get('last.example.com')?.message).toBe('at the end');
    // The first line is far from the end: not read.
    expect(result.has('cut.example.com')).toBe(false);
  });

  it('has no errors without the file, an empty file or names', async () => {
    expect((await getIssuanceErrors(['a.example.com'], { file })).size).toBe(0);
    writeFileSync(file, '');
    expect((await getIssuanceErrors(['a.example.com'], { file })).size).toBe(0);
    expect((await getIssuanceErrors([], { file })).size).toBe(0);
  });
});
