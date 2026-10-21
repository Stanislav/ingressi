/**
 * The environment variables of the web container.
 *
 * Podman's compose provider does not apply the defaults of docker-compose.yml:
 * a variable that is missing from .env reaches the container as the literal
 * "${VARIABLE:-default}" placeholder. Such a value must not be used as a URL
 * or a credential, so it counts as "not set".
 */
import { describe, it, expect, afterEach } from 'vitest';
import { envValue } from '../../src/lib/config';

const ORIGINAL = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL };
});

describe('envValue', () => {
  it('reads a variable that is set', () => {
    process.env.INGRESSI_TEST_VALUE = 'https://caddy:2019';
    expect(envValue('INGRESSI_TEST_VALUE')).toBe('https://caddy:2019');
  });

  it('answers undefined for a variable that is not set', () => {
    delete process.env.INGRESSI_TEST_VALUE;
    expect(envValue('INGRESSI_TEST_VALUE')).toBeUndefined();
  });

  it('answers undefined for an unsubstituted placeholder', () => {
    process.env.INGRESSI_TEST_VALUE = '${INGRESSI_TEST_VALUE:-https://caddy:2019}';
    expect(envValue('INGRESSI_TEST_VALUE')).toBeUndefined();
  });

  it('keeps a value that only looks like a placeholder', () => {
    process.env.INGRESSI_TEST_VALUE = '${not-a-placeholder';
    expect(envValue('INGRESSI_TEST_VALUE')).toBe('${not-a-placeholder');
  });
});
