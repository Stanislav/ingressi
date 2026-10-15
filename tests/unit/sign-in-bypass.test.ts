/**
 * The addresses that skip sign-in (src/lib/sign-in-bypass.ts): what input is
 * accepted and how it is normalized, what is read back from storage, and the
 * invariants that keep a bad entry from widening the bypass.
 */
import { describe, expect, it } from 'vitest';
import { ApiValidationError } from '../../src/lib/api-errors';
import { parseIpRange } from '../../src/lib/access-list-rules';
import {
  MAX_BYPASS_SOURCES,
  normalizeBypassSource,
  normalizeBypassSources,
  readBypassSources,
  touchesPrivateNetworks,
} from '../../src/lib/sign-in-bypass';

describe('normalizeBypassSource', () => {
  it.each([
    ['192.168.1.5', '192.168.1.5'],
    ['  10.0.0.5  ', '10.0.0.5'],
    ['192.168.1.0/24', '192.168.1.0/24'],
    ['2001:db8::/32', '2001:db8::/32'],
    ['2001:DB8:0:0:0:0:0:1', '2001:db8::1'],
    ['::1', '::1'],
    ['private_ranges', 'private_ranges'],
    ['PRIVATE_RANGES', 'private_ranges'],
  ])('accepts %s', (input, expected) => {
    expect(normalizeBypassSource(input)).toEqual({ value: expected });
  });

  it('stores a range as its network address', () => {
    expect(normalizeBypassSource('192.168.1.77/24')).toEqual({ value: '192.168.1.0/24' });
    expect(normalizeBypassSource('10.1.2.3/8')).toEqual({ value: '10.0.0.0/8' });
    expect(normalizeBypassSource('2001:db8::dead:beef/32')).toEqual({ value: '2001:db8::/32' });
  });

  it.each([
    'office.example.com',
    'localhost',
    '999.1.1.1',
    '1.2.3',
    '1.2.3.4.5',
    '10.0.0.0/33',
    '10.0.0.0/-1',
    '10.0.0.0/08',
    '10.0.0.0/8/8',
    '2001:db8::/129',
    'fe80::1%eth0',
    '1.2.3.4-1.2.3.9',
    '{http.request.remote.host}',
    '10.0.0.1"',
    '',
    '   ',
    '*',
    'any',
  ])('refuses %j', (input) => {
    expect('error' in normalizeBypassSource(input)).toBe(true);
  });

  it('refuses a range that matches every address, since that turns sign-in off', () => {
    for (const input of ['0.0.0.0/0', '::/0', '10.0.0.0/0', '2001:db8::/0']) {
      const result = normalizeBypassSource(input);
      expect(result).toHaveProperty('error');
      expect((result as { error: string }).error).toContain('matches every address');
    }
  });

  it('accepts the narrowest wide ranges, which are the administrator\'s call', () => {
    expect(normalizeBypassSource('0.0.0.0/1')).toEqual({ value: '0.0.0.0/1' });
    expect(normalizeBypassSource('::/1')).toEqual({ value: '::/1' });
  });

  it('keeps long junk out of the message', () => {
    const result = normalizeBypassSource('x'.repeat(500)) as { error: string };
    expect(result.error.length).toBeLessThan(150);
  });
});

describe('normalizeBypassSources', () => {
  it('takes an array, or one string separated by commas, spaces and new lines', () => {
    expect(normalizeBypassSources(['10.0.0.5', '192.168.1.0/24'])).toEqual(['10.0.0.5', '192.168.1.0/24']);
    expect(normalizeBypassSources('10.0.0.5, 192.168.1.0/24\n172.16.0.0/12  203.0.113.9')).toEqual([
      '10.0.0.5',
      '192.168.1.0/24',
      '172.16.0.0/12',
      '203.0.113.9',
    ]);
  });

  it('means "none" for undefined, null, empty and blank input', () => {
    expect(normalizeBypassSources(undefined)).toEqual([]);
    expect(normalizeBypassSources(null)).toEqual([]);
    expect(normalizeBypassSources([])).toEqual([]);
    expect(normalizeBypassSources(['', '  '])).toEqual([]);
    expect(normalizeBypassSources('  ,  ')).toEqual([]);
  });

  it('removes repeats, including ones that differ only in spelling', () => {
    expect(normalizeBypassSources(['192.168.1.5/24', '192.168.1.0/24', '192.168.1.0/24', 'private_ranges', 'PRIVATE_RANGES'])).toEqual([
      '192.168.1.0/24',
      'private_ranges',
    ]);
  });

  it('throws a 400 that names the field and the first bad entry', () => {
    expect(() => normalizeBypassSources(['10.0.0.5', 'nope', 'worse'], 'authentik.bypassSources')).toThrow(ApiValidationError);
    expect(() => normalizeBypassSources(['10.0.0.5', 'nope', 'worse'], 'authentik.bypassSources')).toThrow(
      /^authentik\.bypassSources: "nope" is not an IP address, a CIDR range or private_ranges$/
    );
    expect(() => normalizeBypassSources(['0.0.0.0/0'])).toThrow(/matches every address/);
  });

  it('refuses anything that is not a list of strings', () => {
    expect(() => normalizeBypassSources({ 0: '10.0.0.5' })).toThrow(ApiValidationError);
    expect(() => normalizeBypassSources(42)).toThrow(ApiValidationError);
    expect(() => normalizeBypassSources(true)).toThrow(ApiValidationError);
    expect(() => normalizeBypassSources([10])).toThrow(/bypassSources\[0\] must be a string/);
    expect(() => normalizeBypassSources([['10.0.0.5']])).toThrow(/must be a string/);
    expect(() => normalizeBypassSources([null])).toThrow(/must be a string/);
  });

  it(`holds at most ${MAX_BYPASS_SOURCES} entries`, () => {
    const entries = (count: number) => Array.from({ length: count }, (_, index) => `10.${Math.floor(index / 250)}.${index % 250}.0/24`);
    expect(normalizeBypassSources(entries(MAX_BYPASS_SOURCES))).toHaveLength(MAX_BYPASS_SOURCES);
    expect(() => normalizeBypassSources(entries(MAX_BYPASS_SOURCES + 1))).toThrow(/at most 100 entries/);
    expect(() => normalizeBypassSources(entries(MAX_BYPASS_SOURCES * 10 + 1))).toThrow(/at most 100 entries/);
    // Repeats do not count against the limit.
    expect(normalizeBypassSources(Array.from({ length: 300 }, () => '10.0.0.5'))).toEqual(['10.0.0.5']);
  });
});

describe('readBypassSources', () => {
  it('keeps the valid entries of what storage holds and drops the rest', () => {
    expect(readBypassSources(['10.0.0.5', 'nope', '0.0.0.0/0', '::/0', 7, null, '192.168.1.9/24', 'private_ranges', '10.0.0.5'])).toEqual([
      '10.0.0.5',
      '192.168.1.0/24',
      'private_ranges',
    ]);
  });

  it('reads anything that is not a list as no entries', () => {
    for (const value of [undefined, null, 'private_ranges', 10, {}, true]) {
      expect(readBypassSources(value)).toEqual([]);
    }
  });

  it(`never returns more than ${MAX_BYPASS_SOURCES} entries`, () => {
    const stored = Array.from({ length: 500 }, (_, index) => `10.${Math.floor(index / 250)}.${index % 250}.0/24`);
    expect(readBypassSources(stored)).toHaveLength(MAX_BYPASS_SOURCES);
  });
});

describe('touchesPrivateNetworks', () => {
  it('is true for private_ranges and anything inside or around a private network', () => {
    for (const entry of ['private_ranges', '10.0.0.5', '192.168.1.0/24', '172.20.0.0/16', '127.0.0.1', 'fd12::1', '::1', '10.0.0.0/8', '0.0.0.0/1', '128.0.0.0/1', '192.0.0.0/2']) {
      expect(touchesPrivateNetworks([entry]), entry).toBe(true);
    }
  });

  it('is false for public addresses and ranges', () => {
    for (const entry of ['203.0.113.9', '198.51.100.0/24', '8.8.8.8', '2001:db8::/32', '172.32.0.0/16', '11.0.0.0/8']) {
      expect(touchesPrivateNetworks([entry]), entry).toBe(false);
    }
    expect(touchesPrivateNetworks([])).toBe(false);
    expect(touchesPrivateNetworks(['not an address'])).toBe(false);
  });

  it('is true when any entry touches one', () => {
    expect(touchesPrivateNetworks(['203.0.113.9', '10.1.2.3'])).toBe(true);
  });
});

describe('invariants (seeded)', () => {
  // A small deterministic generator, so a failure repeats.
  function random(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state / 0x100000000;
    };
  }

  function entry(next: () => number): string {
    const pick = <T,>(items: T[]) => items[Math.floor(next() * items.length)];
    const octet = () => Math.floor(next() * 256);
    switch (Math.floor(next() * 8)) {
      case 0:
        return `${octet()}.${octet()}.${octet()}.${octet()}`;
      case 1:
        return `${octet()}.${octet()}.${octet()}.${octet()}/${Math.floor(next() * 36)}`;
      case 2:
        return `${(octet() * 256 + octet()).toString(16)}:${octet().toString(16)}::${octet().toString(16)}/${Math.floor(next() * 135)}`;
      case 3:
        return pick(['private_ranges', 'PRIVATE_RANGES', 'private_range', ' private_ranges ']);
      case 4:
        return pick(['', ' ', 'localhost', 'a.b.c.d', '1.2.3', '256.1.1.1', '1.1.1.1/', '/8', '::::', '1::2::3', '0x7f.0.0.1', '010.0.0.1']);
      case 5:
        return `${octet()}.${octet()}.${octet()}.${octet()}/${pick(['0', '00', '1', '8', '32', '33', '-1', '1e1'])}`;
      case 6:
        return pick(['0.0.0.0/0', '::/0', '0.0.0.0/00', '::0/0']);
      default:
        return String.fromCharCode(...Array.from({ length: 1 + Math.floor(next() * 12) }, () => 32 + Math.floor(next() * 95)));
    }
  }

  it('whatever is accepted is canonical, narrower than everything, and stays the same when normalized again', () => {
    for (let seed = 1; seed <= 300; seed += 1) {
      const next = random(seed);
      const input = Array.from({ length: 1 + Math.floor(next() * 6) }, () => entry(next));
      let accepted: string[];
      try {
        accepted = normalizeBypassSources(input);
      } catch (error) {
        expect(error).toBeInstanceOf(ApiValidationError);
        continue;
      }
      expect(accepted.length).toBeLessThanOrEqual(MAX_BYPASS_SOURCES);
      expect(new Set(accepted).size).toBe(accepted.length);
      for (const value of accepted) {
        if (value === 'private_ranges') continue;
        const range = parseIpRange(value);
        expect(range, `${value} from ${JSON.stringify(input)}`).not.toBeNull();
        expect(range!.prefix).toBeGreaterThan(0);
        expect(range!.text).toBe(value);
      }
      expect(normalizeBypassSources(accepted)).toEqual(accepted);
      expect(readBypassSources(accepted)).toEqual(accepted);
    }
  });

  it('what storage returns is always a subset of what would be accepted, never wider', () => {
    for (let seed = 1000; seed <= 1300; seed += 1) {
      const next = random(seed);
      const stored = Array.from({ length: Math.floor(next() * 12) }, () => entry(next));
      const read = readBypassSources(stored);
      expect(read.length).toBeLessThanOrEqual(MAX_BYPASS_SOURCES);
      for (const value of read) {
        expect('error' in normalizeBypassSource(value)).toBe(false);
        expect(normalizeBypassSource(value)).toEqual({ value });
        if (value !== 'private_ranges') expect(parseIpRange(value)!.prefix).toBeGreaterThan(0);
      }
    }
  });
});
