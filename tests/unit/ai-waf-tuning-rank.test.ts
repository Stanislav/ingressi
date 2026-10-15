import { describe, expect, it } from 'vitest';
import {
  MIN_SUGGESTION_SCORE,
  SEVERE_ATTACK_MIN_SCORE,
  compareSuggestions,
  isProbePath,
  pathSignals,
  rankCandidate,
  ruleFamily,
  type CandidateStats,
} from '@/ee/ai/waf-tuning-rank';

function stats(overrides: Partial<CandidateStats> = {}): CandidateStats {
  return {
    ruleId: 920420,
    events: 400,
    clients: 60,
    activeDays: 10,
    blockedEvents: 0,
    criticalEvents: 0,
    averageAnomalyScore: null,
    cleanClients: 55,
    normalClients: 50,
    pathPrefixes: [{ prefix: '/api/upload', events: 380, clients: 58, examplePaths: ['/api/upload/chunk'] }],
    ...overrides,
  };
}

describe('ruleFamily', () => {
  it('knows the CRS families and which are attack-critical', () => {
    expect(ruleFamily(942100)).toEqual({ name: 'SQL injection', critical: true });
    expect(ruleFamily(932160)).toEqual({ name: 'Remote code execution', critical: true });
    expect(ruleFamily(941100)).toEqual({ name: 'Cross-site scripting', critical: false });
    expect(ruleFamily(920420)).toEqual({ name: 'Protocol enforcement', critical: false });
    // Anomaly evaluation, initialization and custom rules are never suggested.
    expect(ruleFamily(949110)).toBeNull();
    expect(ruleFamily(901001)).toBeNull();
    expect(ruleFamily(9001)).toBeNull();
  });
});

describe('rankCandidate', () => {
  it('rates a widespread, detection-only rule hit by normal clients as high confidence', () => {
    const ranking = rankCandidate(stats());
    expect(ranking.confidence).toBe('high');
    expect(ranking.score).toBeGreaterThanOrEqual(70);
    expect(ranking.attackCritical).toBe(false);
    expect(ranking.reasons).toEqual(expect.arrayContaining([
      'Matched 400 times for 60 different clients on 10 days',
      '100% of the matches did not block the request (detection-only or below the anomaly threshold)',
      '55 of 60 clients triggered no other WAF rule',
      '50 of 60 clients also made successful requests to this host',
      '95% of the matches are under /api/upload',
    ]));
  });

  it('never rates an attack-critical family as high confidence', () => {
    const sqli = rankCandidate(stats({ ruleId: 942100 }));
    expect(sqli.attackCritical).toBe(true);
    expect(sqli.confidence).toBe('medium');
    expect(sqli.reasons.join(' ')).toMatch(/SQL injection rule: .* never a high-confidence suggestion/);
  });

  it('rates attack-critical rules with severe matches as low confidence', () => {
    for (const severe of [
      { criticalEvents: 300 },
      { averageAnomalyScore: 25 },
      { blockedEvents: 380 },
    ]) {
      expect(rankCandidate(stats({ ruleId: 932160, ...severe })).confidence).toBe('low');
    }
  });

  it('does not suggest blocked matches from clients that also trigger other rules', () => {
    const ranking = rankCandidate(stats({ ruleId: 941100, clients: 6, activeDays: 2, blockedEvents: 380, criticalEvents: 380, cleanClients: 1, normalClients: 0, averageAnomalyScore: 20 }));
    expect(ranking.confidence).toBe('low');
    expect(ranking.score).toBeLessThan(MIN_SUGGESTION_SCORE);
    expect(ranking.suggest).toBe(false);
    expect(rankCandidate(stats()).suggest).toBe(true);
  });

  it('ignores the traffic signal when there is no traffic data', () => {
    const ranking = rankCandidate(stats({ normalClients: null }));
    expect(ranking.confidence).toBe('high');
    expect(ranking.reasons.join(' ')).not.toMatch(/successful requests/);
  });

  it('needs many clean clients for high confidence', () => {
    expect(rankCandidate(stats({ cleanClients: 20 })).confidence).not.toBe('high');
    expect(rankCandidate(stats({ clients: 8, cleanClients: 8, normalClients: 8 })).confidence).not.toBe('high');
  });
});

describe('isProbePath', () => {
  it('knows the paths scanners ask for', () => {
    for (const path of [
      '/.env',
      '/.env.local',
      '/.git/config',
      '/admin/.git/HEAD',
      '/.aws/credentials',
      '/.htaccess',
      '/.DS_Store',
      '/%2e%2e/%2e%2e/etc/passwd',
      '/static/../../etc/shadow',
      '/etc/passwd',
      '/proc/self/environ',
      '/windows/win.ini',
      '/wp-config.php',
      '/wp-config.php.bak',
      '/backup.sql',
      '/site.tar.gz.old',
      '/database.sqlite3',
      '/composer.json',
      '/web.config',
      '/id_rsa',
      '/uploads/c99.php',
      '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
      '/.env.backup',
      '/.env~',
      '/wp-config.php~',
      '/index.php~',
      '/.git/config~',
      '/.claude/settings.local.json',
      '/terraform.tfstate.backup',
      '/terraform.tfvars',
      '/firebase-config.js',
    ]) {
      expect(isProbePath(path), path).toBe(true);
    }
  });

  it('leaves the pages of applications that really run alone', () => {
    for (const path of [
      '/',
      '/search',
      '/api/upload/chunk',
      '/Items/3f6c2a0e-8a4b-4b8e-9e0f-1a2b3c4d5e6f/PlaybackInfo',
      '/.well-known/acme-challenge/abc',
      '/.well-known/openid-configuration',
      '/wp-admin/admin-ajax.php',
      '/wp-login.php',
      '/phpmyadmin/index.php',
      '/cgi-bin/status',
      '/actuator/health',
      '/downloads/report.zip',
      '/assets/app.min.js',
      '/blog/how-to-use-.env-files',
      '/web/config.json',
      '/api/v1/request',
      '/Microsoft-Server-ActiveSync',
      '/%E0%A4%A',
    ]) {
      expect(isProbePath(path), path).toBe(false);
    }
  });
});

describe('pathSignals', () => {
  it('shares the matches between probe and other paths', () => {
    const signals = pathSignals([
      { path: '/.env', events: 60 },
      { path: '/.git/config', events: 40 },
      { path: '/index.php', events: 100 },
    ]);
    expect(signals.probeShare).toBe(0.5);
    expect(signals.scattered).toBe(false);
  });

  it('finds a scanner in matches spread over many unrelated paths', () => {
    const many = Array.from({ length: 60 }, (_, index) => ({ path: `/dir${index}/index.php`, events: 5 }));
    expect(pathSignals(many)).toMatchObject({ distinctPaths: 60, scattered: true });
  });

  it('does not call one endpoint with a different ID per request scattered', () => {
    const ids = Array.from({ length: 80 }, (_, index) => ({ path: `/Items/${String(index).padStart(8, '0')}0000/PlaybackInfo`, events: 5 }));
    expect(pathSignals(ids)).toMatchObject({ distinctPaths: 1, scattered: false });
    expect(pathSignals([])).toMatchObject({ probeShare: 0, scattered: false });
  });
});

describe('rankCandidate and scanners', () => {
  // A scanner looking for secrets: many clients over many days, each only triggering this rule.
  const SCANNER = {
    ruleId: 930130,
    events: 3091,
    clients: 92,
    activeDays: 15,
    blockedEvents: 3091,
    criticalEvents: 3091,
    averageAnomalyScore: 5,
    cleanClients: 45,
    normalClients: 23,
    pathPrefixes: [
      { prefix: '/.env', events: 68, clients: 52, examplePaths: ['/.env'] },
      { prefix: '/.git/config', events: 63, clients: 51, examplePaths: ['/.git/config'] },
    ],
  };
  const PROBES = [
    { path: '/.env', events: 68 },
    { path: '/.git/config', events: 63 },
    { path: '/.env.local', events: 41 },
    { path: '/backup.sql', events: 30 },
    { path: '/wp-config.php.bak', events: 22 },
  ];

  it('does not suggest severe attack-class matches that only look widespread', () => {
    const ranking = rankCandidate(stats(SCANNER));
    expect(ranking.score).toBeLessThan(SEVERE_ATTACK_MIN_SCORE);
    expect(ranking.score).toBeGreaterThanOrEqual(MIN_SUGGESTION_SCORE);
    expect(ranking.suggest).toBe(false);
  });

  it('still suggests severe attack-class matches that visitors cause', () => {
    // Blocked searches of normal clients that trigger nothing else.
    const ranking = rankCandidate(stats({ ruleId: 942100, blockedEvents: 380, criticalEvents: 380, cleanClients: 58, normalClients: 56, averageAnomalyScore: 5 }));
    expect(ranking.confidence).toBe('low');
    expect(ranking.score).toBeGreaterThanOrEqual(SEVERE_ATTACK_MIN_SCORE);
    expect(ranking.suggest).toBe(true);
  });

  it('does not suggest matches on probe paths, however normal the clients look', () => {
    const quiet = stats({ ruleId: 930130, cleanClients: 58, normalClients: 56 });
    expect(rankCandidate(quiet).suggest).toBe(true);
    const ranking = rankCandidate({ ...quiet, paths: PROBES });
    expect(ranking.suggest).toBe(false);
    expect(ranking.confidence).toBe('low');
    expect(ranking.reasons.join(' ')).toMatch(/100% of the matches ask for files a website does not serve/);
  });

  it('does not suggest an attack-critical rule matching all over a site, but does one matching an endpoint', () => {
    const spread = Array.from({ length: 50 }, (_, index) => ({ path: `/section-${index}/page`, events: 8 }));
    const ranking = rankCandidate({ ...stats({ ruleId: 932160, cleanClients: 58, normalClients: 56 }), paths: spread });
    expect(ranking.suggest).toBe(false);
    expect(ranking.reasons.join(' ')).toMatch(/spread over 50 different paths/);
    // A rule outside the attack-critical families can match anywhere (a header, the method).
    expect(rankCandidate({ ...stats({ ruleId: 920350 }), paths: spread }).suggest).toBe(true);
    expect(rankCandidate({ ...stats({ ruleId: 932160 }), paths: [{ path: '/api/upload', events: 380 }, { path: '/', events: 20 }] }).suggest).toBe(true);
  });

  it('works without path data', () => {
    expect(rankCandidate({ ...stats(), paths: undefined }).suggest).toBe(true);
    expect(rankCandidate({ ...stats(), paths: [] }).suggest).toBe(true);
  });
});

describe('compareSuggestions', () => {
  it('orders by confidence, then by volume', () => {
    const items = [
      { id: 'low-big', confidence: 'low' as const, events: 9000, clients: 900, score: 40 },
      { id: 'high-small', confidence: 'high' as const, events: 50, clients: 12, score: 75 },
      { id: 'high-big', confidence: 'high' as const, events: 500, clients: 40, score: 72 },
      { id: 'medium', confidence: 'medium' as const, events: 5000, clients: 300, score: 60 },
    ];
    expect(items.sort(compareSuggestions).map((item) => item.id)).toEqual(['high-big', 'high-small', 'medium', 'low-big']);
  });
});
