/**
 * Choosing where a WAF exclusion applies: the paths a request's path can be
 * narrowed or widened to, IDs in a path (an exact path with one matches that
 * one request only), the sentence for a scope, and field problems.
 */
import { describe, expect, it } from 'vitest';
import {
  describeScope,
  idSegmentOf,
  looksLikeId,
  pathAboveId,
  pathChoices,
  pathProblem,
  variableProblem,
} from '@/src/lib/waf-exclusion-scope';

describe('looksLikeId', () => {
  it('recognises the identifiers that differ from one request to the next', () => {
    expect(looksLikeId('8171a144e5a97d6eb7ff48ff23262467')).toBe(true);
    expect(looksLikeId('3f2504e0-4f89-11d3-9a0c-0305e82c3301')).toBe(true);
    expect(looksLikeId('1234567')).toBe(true);
    expect(looksLikeId('01ARZ3NDEKTSV4RRFFQ69G5FAV')).toBe(true);
  });

  it('leaves names, short numbers and slugs alone', () => {
    for (const segment of ['Items', 'PlaybackInfo', 'v1', '2024', 'api', 'deadbeef', 'user_settings_page', 'my-long-article-title-2024']) {
      expect(looksLikeId(segment), segment).toBe(false);
    }
  });
});

describe('pathAboveId', () => {
  it('is the directory above the first ID', () => {
    expect(pathAboveId('/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo')).toBe('/Items/');
    expect(pathAboveId('/api/v1/users/1234567/posts/9876543')).toBe('/api/v1/users/');
  });

  it('is null without an ID, or when the path starts with one', () => {
    expect(pathAboveId('/api/public/otel/v1/traces')).toBeNull();
    expect(pathAboveId('/8171a144e5a97d6eb7ff48ff23262467/x')).toBeNull();
    expect(pathAboveId('/')).toBeNull();
  });

  it('names the segment that looks like an ID', () => {
    expect(idSegmentOf('/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo')).toBe('8171a144e5a97d6eb7ff48ff23262467');
    expect(idSegmentOf('/api/traces')).toBeNull();
  });
});

describe('pathChoices', () => {
  it('goes from every path to the exact path, through each directory', () => {
    expect(pathChoices('/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo')).toEqual([
      { key: 'any', path: null, pathMatch: null },
      { key: 'prefix:/Items/', path: '/Items/', pathMatch: 'prefix' },
      { key: 'prefix:/Items/8171a144e5a97d6eb7ff48ff23262467/', path: '/Items/8171a144e5a97d6eb7ff48ff23262467/', pathMatch: 'prefix' },
      { key: 'exact', path: '/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo', pathMatch: 'exact' },
    ]);
  });

  it('offers only every path and the path itself for a top-level path', () => {
    expect(pathChoices('/login').map((choice) => choice.path)).toEqual([null, '/login']);
    expect(pathChoices('/api/x/').map((choice) => choice.path)).toEqual([null, '/api/', '/api/x/']);
  });

  it('offers only every path when there is no request path', () => {
    expect(pathChoices(null)).toEqual([{ key: 'any', path: null, pathMatch: null }]);
  });

  it('keeps a deep path to a few directories: the first ones and the nearest', () => {
    const choices = pathChoices('/a/b/c/d/e/f/g/h/file');
    expect(choices.map((choice) => choice.path)).toEqual([null, '/a/', '/a/b/', '/a/b/c/d/e/f/', '/a/b/c/d/e/f/g/', '/a/b/c/d/e/f/g/h/', '/a/b/c/d/e/f/g/h/file']);
  });

  it('only offers paths a form accepts', () => {
    for (const choice of pathChoices('/Items/8171a144e5a97d6eb7ff48ff23262467/PlaybackInfo')) {
      expect(pathProblem(choice.path ?? ''), choice.key).toBeNull();
    }
  });
});

describe('describeScope', () => {
  it('says the host and the path', () => {
    expect(describeScope({ hostName: 'Docs', path: '/api/', pathMatch: 'prefix' })).toBe('on Docs, for paths starting with /api/');
    expect(describeScope({ hostName: 'Docs', path: '/api/x', pathMatch: 'exact' })).toBe('on Docs, for exactly /api/x');
    expect(describeScope({ hostName: null, path: '  ', pathMatch: 'exact' })).toBe('on every host that follows the global settings, for every path');
  });
});

describe('field problems', () => {
  it('accepts an empty path and an empty variable: every path, every variable', () => {
    expect(pathProblem('')).toBeNull();
    expect(pathProblem('   ')).toBeNull();
    expect(variableProblem('')).toBeNull();
  });

  it('words a refused path for a form', () => {
    expect(pathProblem('Items/x')).toMatch(/^The path must start with \//);
    expect(pathProblem('/a//b')).toMatch(/^The path must not contain/);
    expect(pathProblem('/a b')).toMatch(/^The path must start with/);
  });

  it('words a refused variable for a form', () => {
    expect(variableProblem('NOPE:x')).toMatch(/^The variable must name one of/);
    expect(variableProblem('REQUEST_BODY:x')).toBe('REQUEST_BODY takes no name after a colon');
    expect(variableProblem('ARGS:json.MaxStreamingBitrate')).toBeNull();
    expect(variableProblem('args:content')).toBeNull();
    const badKey = variableProblem('ARGS:/x/');
    expect(badKey).toMatch(/^The name after ARGS:/);
  });
});
