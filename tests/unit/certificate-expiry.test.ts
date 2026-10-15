/**
 * Reading the expiry of the certificates Caddy serves for the certificates
 * page (getManagedCertificateExpiry in src/lib/managed-certificates.ts, the
 * reader alerting uses too) against a local TLS server standing in for
 * Caddy's HTTPS listener.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import tls from 'node:tls';
import { createSelfSignedServerCertificate } from '../helpers/certs';
import {
  caddyTlsAddress,
  clearCertificateExpiryCache,
  getManagedCertificateExpiry,
  getManagedCertificateReadings,
  setManagedCertificateProbeForTests,
} from '@/src/lib/managed-certificates';

const DAY = 86_400_000;
let server: tls.Server;
let address: string;
let handshakes: string[] = [];

beforeAll(async () => {
  const plain = createSelfSignedServerCertificate('app.example.test', ['app.example.test'], 60);
  const wildcard = createSelfSignedServerCertificate('*.wild.example.test', ['*.wild.example.test'], 20);
  const plainContext = tls.createSecureContext({ cert: plain.certificatePem, key: plain.privateKeyPem });
  const wildContext = tls.createSecureContext({ cert: wildcard.certificatePem, key: wildcard.privateKeyPem });
  server = tls.createServer(
    {
      cert: plain.certificatePem,
      key: plain.privateKeyPem,
      SNICallback: (servername, callback) => {
        handshakes.push(servername);
        callback(null, servername.endsWith('.wild.example.test') ? wildContext : plainContext);
      },
    },
    (socket) => {
      socket.on('error', () => {});
      socket.end();
    }
  );
  server.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  address = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});

const testAddress = process.env.CADDY_TLS_ADDRESS;

afterAll(() => {
  process.env.CADDY_TLS_ADDRESS = testAddress;
  clearCertificateExpiryCache();
  server.close();
});

beforeEach(() => {
  process.env.CADDY_TLS_ADDRESS = address;
  clearCertificateExpiryCache();
  handshakes = [];
});

describe('getManagedCertificateExpiry', () => {
  it('reads the validity, issuer and key of the certificate served for a domain', async () => {
    const result = await getManagedCertificateExpiry(['App.Example.Test ']);
    const cert = result.get('app.example.test');
    expect(cert).toBeDefined();
    expect(cert!.domain).toBe('app.example.test');
    expect(cert!.issuer).toBe('Ingressi E2E');
    expect(cert!.keyType).toBe('RSA 2048');
    const daysLeft = (new Date(cert!.validTo).getTime() - Date.now()) / DAY;
    expect(daysLeft).toBeGreaterThan(58);
    expect(daysLeft).toBeLessThanOrEqual(60);
    expect(new Date(cert!.validFrom).getTime()).toBeLessThanOrEqual(Date.now());
  });

  it('asks for a wildcard name with a label under it', async () => {
    const result = await getManagedCertificateExpiry(['*.wild.example.test']);
    expect(result.get('*.wild.example.test')?.validTo).toBeDefined();
    expect(handshakes).toEqual(['tls-check.wild.example.test']);
  });

  it('ignores a certificate that does not name the domain', async () => {
    const result = await getManagedCertificateExpiry(['other.example.test']);
    expect(result.size).toBe(0);
  });

  it('caches results, found or not', async () => {
    await getManagedCertificateExpiry(['app.example.test', 'other.example.test']);
    await getManagedCertificateExpiry(['app.example.test', 'other.example.test']);
    expect(handshakes.sort()).toEqual(['app.example.test', 'other.example.test']);
  });

  it('never asks for addresses or malformed names', async () => {
    const result = await getManagedCertificateExpiry(['192.0.2.1', '2001:db8::1', 'bad name', '', 'a..b']);
    expect(result.size).toBe(0);
    expect(handshakes).toEqual([]);
  });

  it('returns nothing when Caddy cannot be reached', async () => {
    // A port nothing listens on any more: the connection is refused.
    const closed = net.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    process.env.CADDY_TLS_ADDRESS = `127.0.0.1:${port}`;
    expect((await getManagedCertificateExpiry(['app.example.test'])).size).toBe(0);
  });

  it('stops waiting after waitMs when a handshake hangs', async () => {
    // Accepts the connection and never answers the ClientHello.
    const sockets: net.Socket[] = [];
    const silent = net.createServer((socket) => {
      socket.on('error', () => {});
      sockets.push(socket);
    });
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    process.env.CADDY_TLS_ADDRESS = `127.0.0.1:${(silent.address() as AddressInfo).port}`;
    const started = Date.now();
    const result = await getManagedCertificateExpiry(['hang.example.test'], { waitMs: 150 });
    expect(result.size).toBe(0);
    expect(Date.now() - started).toBeLessThan(1500);
    for (const socket of sockets) socket.destroy();
    silent.close();
  });
});

describe('getManagedCertificateReadings', () => {
  it('tells a served certificate from none, and from a handshake that did not work', async () => {
    try {
      const plain = createSelfSignedServerCertificate('app.example.test', ['app.example.test'], 60);
      setManagedCertificateProbeForTests(async (servername) => {
        if (servername === 'app.example.test') return { kind: 'certificate', pem: plain.certificatePem };
        if (servername === 'none.example.test') return { kind: 'missing' };
        if (servername === 'refused.example.test') return { kind: 'unreachable', code: 'ECONNREFUSED' };
        if (servername === 'odd.example.test') return { kind: 'tls_error', code: 'ERR_SSL_SOMETHING' };
        return { kind: 'certificate', pem: plain.certificatePem };
      });

      const result = await getManagedCertificateReadings([
        'app.example.test', 'none.example.test', 'refused.example.test', 'odd.example.test', 'other.example.test',
      ]);

      expect(result.get('app.example.test')).toMatchObject({ kind: 'served', expiry: { domain: 'app.example.test' } });
      expect(result.get('none.example.test')).toMatchObject({ kind: 'none' });
      // A certificate that does not name the domain is no certificate for it.
      expect(result.get('other.example.test')).toMatchObject({ kind: 'none' });
      expect(result.get('refused.example.test')).toMatchObject({ kind: 'unavailable' });
      expect(result.get('odd.example.test')).toMatchObject({ kind: 'unavailable' });
      expect(Date.parse((result.get('none.example.test') as { checkedAt: string }).checkedAt)).not.toBeNaN();
      // The expiry reader keeps answering with the served ones only.
      expect([...(await getManagedCertificateExpiry(['app.example.test', 'none.example.test'])).keys()]).toEqual(['app.example.test']);
    } finally {
      setManagedCertificateProbeForTests(null);
    }
  });

  it('leaves out a domain whose first handshake has not finished', async () => {
    try {
      // Answers after the wait is over; waited for below, so the shared handshake slot is free again for the next test.
      setManagedCertificateProbeForTests(() => new Promise((resolve) => setTimeout(() => resolve({ kind: 'missing' }), 200)));
      const result = await getManagedCertificateReadings(['slow.example.test'], { waitMs: 50 });
      expect(result.size).toBe(0);
      await new Promise((resolve) => setTimeout(resolve, 300));
    } finally {
      setManagedCertificateProbeForTests(null);
    }
  });
});

describe('caddyTlsAddress', () => {
  it('takes CADDY_TLS_ADDRESS, including bracketed IPv6, and rejects an invalid port', () => {
    process.env.CADDY_TLS_ADDRESS = '[::1]:8443';
    expect(caddyTlsAddress()).toEqual({ host: '::1', port: 8443 });
    process.env.CADDY_TLS_ADDRESS = 'caddy:99999';
    expect(caddyTlsAddress()).toBeNull();
  });

  it("defaults to the admin API's host on port 443", () => {
    delete process.env.CADDY_TLS_ADDRESS;
    const target = caddyTlsAddress();
    expect(target?.port).toBe(443);
    expect(target?.host).toBe(new URL(process.env.CADDY_API_URL ?? 'http://caddy:2019').hostname);
  });

  it('reads nothing when the checks are off', async () => {
    process.env.CADDY_TLS_ADDRESS = 'off';
    expect((await getManagedCertificateExpiry(['app.example.test'])).size).toBe(0);
    expect(handshakes).toEqual([]);
  });
});

describe('one reader for the page and alerting', () => {
  it('shares one handshake per name between the page and the alert checks', async () => {
    const probe = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      return { kind: 'missing' as const };
    });
    setManagedCertificateProbeForTests(probe);
    try {
      // Both ask for the same name at once; one handshake answers both, and the result is cached for the next caller.
      await Promise.all([getManagedCertificateExpiry(['shared.example.test']), getManagedCertificateExpiry(['shared.example.test'])]);
      await getManagedCertificateExpiry(['shared.example.test']);
      expect(probe).toHaveBeenCalledTimes(1);
      expect(probe).toHaveBeenCalledWith('shared.example.test');
    } finally {
      setManagedCertificateProbeForTests(null);
    }
  });

  it('runs at most six handshakes at a time', async () => {
    let running = 0;
    let peak = 0;
    setManagedCertificateProbeForTests(async () => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((resolve) => setTimeout(resolve, 10));
      running--;
      return { kind: 'missing' as const };
    });
    try {
      const names = Array.from({ length: 20 }, (_, i) => `n${i}.example.test`);
      await getManagedCertificateExpiry(names, { waitMs: 2000 });
      expect(peak).toBe(6);
    } finally {
      setManagedCertificateProbeForTests(null);
    }
  });
});
