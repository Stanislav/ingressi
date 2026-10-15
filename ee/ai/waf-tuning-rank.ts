// SPDX-License-Identifier: Elastic-2.0
/**
 * Ranking of WAF tuning candidates: how likely a rule firing on a host is a
 * false positive. Pure functions, no I/O.
 *
 * Signals of a false positive: many different clients over several days,
 * mostly detection-only (not blocked) or low-severity matches, clients that
 * trigger nothing else and that otherwise use the site normally, and matches
 * concentrated under one path. Rules of attack-critical families (SQL
 * injection, remote code execution, ...) never reach "high" confidence, and
 * only "low" when their matches are severe.
 *
 * Scanners look like false positives by those signals (many clients over many
 * days, each triggering a single rule), so the paths of the matches decide
 * too: requests for files a website does not serve (/.env, /.git/config,
 * backups, system files) are attacks, never a rule misreading a visitor, and
 * matches spread over many unrelated paths are a scanner trying them, not one
 * endpoint the rule misreads.
 */
import { looksLikeId } from "@/src/lib/waf-exclusion-scope";
import type { PathPrefixEvidence, SuggestionConfidence } from "./types";

/** Minimum evidence for a candidate at all. */
export const MIN_CLIENTS = 5;
export const MIN_ACTIVE_DAYS = 2;
export const MIN_EVENTS = 10;
/** Successful requests (beyond its WAF matches) that make a client look normal. */
export const NORMAL_CLIENT_MIN_OK_REQUESTS = 3;

const HIGH_SCORE = 0.7;
const MEDIUM_SCORE = 0.5;
/** Below this score the matches look like real attacks, not a false positive: nothing is suggested. */
export const MIN_SUGGESTION_SCORE = 45;
/**
 * Severe matches of an attack-critical family (mostly blocked, critical or
 * with a high anomaly score) need more: a rule that keeps catching real
 * attacks also looks widespread and persistent, so only clients that behave
 * like visitors (no other rule, normal traffic) lift it over this.
 */
export const SEVERE_ATTACK_MIN_SCORE = 55;
/** From this share of the matches on probe paths, nothing is suggested. */
export const PROBE_SHARE_LIMIT = 0.5;
/** Matches over at least this many different paths, the busiest three holding less than SCATTER_TOP_SHARE, are a scanner's. */
export const SCATTER_MIN_PATHS = 30;
export const SCATTER_TOP_SHARE = 0.3;

type Family = { from: number; to: number; name: string; critical: boolean };

/** OWASP CRS rule families that tuning suggestions cover (anomaly evaluation and initialization are excluded). */
export const CRS_FAMILIES: readonly Family[] = [
  { from: 911000, to: 911999, name: "Method enforcement", critical: false },
  { from: 913000, to: 913999, name: "Scanner detection", critical: false },
  { from: 920000, to: 920999, name: "Protocol enforcement", critical: false },
  { from: 921000, to: 921999, name: "Protocol attack", critical: false },
  { from: 922000, to: 922999, name: "Multipart attack", critical: false },
  { from: 930000, to: 930999, name: "Local file inclusion", critical: true },
  { from: 931000, to: 931999, name: "Remote file inclusion", critical: true },
  { from: 932000, to: 932999, name: "Remote code execution", critical: true },
  { from: 933000, to: 933999, name: "PHP injection", critical: true },
  { from: 934000, to: 934999, name: "Generic attack (Node.js, Python, SSRF)", critical: true },
  { from: 941000, to: 941999, name: "Cross-site scripting", critical: false },
  { from: 942000, to: 942999, name: "SQL injection", critical: true },
  { from: 943000, to: 943999, name: "Session fixation", critical: false },
  { from: 944000, to: 944999, name: "Java attack", critical: true },
  { from: 950000, to: 950999, name: "Data leakage", critical: false },
  { from: 951000, to: 951999, name: "SQL error leakage", critical: false },
  { from: 952000, to: 952999, name: "Java error leakage", critical: false },
  { from: 953000, to: 953999, name: "PHP error leakage", critical: false },
  { from: 954000, to: 954999, name: "IIS error leakage", critical: false },
  { from: 955000, to: 955999, name: "Web shell", critical: true },
  { from: 956000, to: 956999, name: "Ruby error leakage", critical: false },
];

export const CANDIDATE_RULE_MIN = 911000;
export const CANDIDATE_RULE_MAX = 956999;

export function ruleFamily(ruleId: number): { name: string; critical: boolean } | null {
  const family = CRS_FAMILIES.find((entry) => ruleId >= entry.from && ruleId <= entry.to);
  return family ? { name: family.name, critical: family.critical } : null;
}

const SENSITIVE_NAMES = new Set([
  "wp-config.php", "config.php", "configuration.php", "web.config", "composer.json", "composer.lock", "package.json",
  "package-lock.json", "yarn.lock", "docker-compose.yml", "docker-compose.yaml", "dockerfile", "id_rsa", "id_dsa",
  "id_ed25519", "credentials", "credentials.json", "secrets.json", "appsettings.json", "parameters.yml", "database.yml",
  "settings.py", "local.settings.json", "phpinfo.php", "info.php", "adminer.php", "samconfig.toml", "firebase-config.js",
  "firebaseconfig.js", "serviceaccountkey.json",
]);
const SENSITIVE_EXTENSION = /\.(?:bak|old|orig|sql|swp|sqlite3?|db|dump|pwd|ini|conf|config|htpasswd|pem|p12|pfx|tfvars|tfstate|backup)$/;
const SYSTEM_PATH = /(?:^|\/)(?:etc\/(?:passwd|shadow|group|hosts|issue)|proc\/(?:self|version|cpuinfo)|windows\/(?:win\.ini|system32)|winnt\/|var\/log\/)/;
const WEBSHELL = /(?:^|\/)(?:c99|r57|wso|b374k|alfa|shell|cmd|eval-stdin)\.php$/;

/**
 * Whether a request path asks for something a website does not serve to
 * visitors: dot-files and dot-folders (/.env, /.git/config, /.claude/settings.json;
 * /.well-known/ is the exception), `..` segments, configuration files, backups
 * (`index.php~`, `.bak`, `.sql`) and dumps, system files and web shell names. Pages of an application that
 * really runs (WordPress, phpMyAdmin, ...) are not on the list: those are where
 * real false positives happen.
 */
export function isProbePath(rawPath: string): boolean {
  let path = rawPath;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    // keep the path as it is
  }
  path = path.toLowerCase().replace(/\\/g, "/");
  const segments = path.split("/").filter((segment) => segment !== "");
  if (segments.some((segment) => segment === "..")) return true;
  if (segments.some((segment) => segment.startsWith(".") && segment !== "." && segment !== ".well-known")) return true;
  const last = segments[segments.length - 1] ?? "";
  // A trailing ~ is an editor's backup copy (index.php~, wp-config.php~).
  return last.endsWith("~") || SENSITIVE_NAMES.has(last) || SENSITIVE_EXTENSION.test(last) || SYSTEM_PATH.test(path) || WEBSHELL.test(path);
}

/** One request path (query string removed) of a candidate's matches and how many matches it has. */
export type PathCount = { path: string; events: number };

export type PathSignals = {
  /** Share of the counted matches on probe paths. */
  probeShare: number;
  /** Different paths, with ID-like segments folded together. */
  distinctPaths: number;
  /** Share of the counted matches on the three busiest of them. */
  topShare: number;
  /** Many unrelated paths, none of them busy: a scanner trying paths. */
  scattered: boolean;
};

function foldIds(path: string): string {
  return path
    .toLowerCase()
    .split("/")
    .map((segment) => (looksLikeId(segment) ? "{id}" : segment))
    .join("/");
}

export function pathSignals(paths: readonly PathCount[]): PathSignals {
  const total = paths.reduce((sum, entry) => sum + entry.events, 0);
  if (total <= 0) return { probeShare: 0, distinctPaths: 0, topShare: 0, scattered: false };
  const probe = paths.reduce((sum, entry) => sum + (isProbePath(entry.path) ? entry.events : 0), 0);
  const folded = new Map<string, number>();
  for (const entry of paths) {
    const key = foldIds(entry.path);
    folded.set(key, (folded.get(key) ?? 0) + entry.events);
  }
  const top = [...folded.values()].sort((a, b) => b - a).slice(0, 3).reduce((sum, events) => sum + events, 0);
  const topShare = top / total;
  return {
    probeShare: probe / total,
    distinctPaths: folded.size,
    topShare,
    scattered: folded.size >= SCATTER_MIN_PATHS && topShare < SCATTER_TOP_SHARE,
  };
}

export type CandidateStats = {
  ruleId: number;
  events: number;
  clients: number;
  activeDays: number;
  blockedEvents: number;
  criticalEvents: number;
  /** Average total inbound anomaly score of the events that reported one; null when none did. */
  averageAnomalyScore: number | null;
  cleanClients: number;
  /** null without traffic data */
  normalClients: number | null;
  pathPrefixes: PathPrefixEvidence[];
  /** The busiest request paths of the matches; absent when they could not be read. */
  paths?: PathCount[];
};

export type CandidateRanking = {
  /** Whether the candidate looks enough like a false positive to be suggested at all. */
  suggest: boolean;
  score: number;
  confidence: SuggestionConfidence;
  family: string | null;
  attackCritical: boolean;
  reasons: string[];
};

function clamp(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

export function rankCandidate(stats: CandidateStats): CandidateRanking {
  const family = ruleFamily(stats.ruleId);
  const attackCritical = family?.critical ?? false;
  const events = Math.max(stats.events, 1);
  const clients = Math.max(stats.clients, 1);
  const blockedShare = stats.blockedEvents / events;
  const criticalShare = stats.criticalEvents / events;
  const cleanShare = stats.cleanClients / clients;
  const normalShare = stats.normalClients === null ? null : stats.normalClients / clients;
  const topPrefix = stats.pathPrefixes[0];
  const prefixShare = topPrefix ? topPrefix.events / events : 0;

  const spread = clamp(Math.log10(clients) / 2); // 10 clients → 0.5, 100 → 1
  const persistence = clamp(stats.activeDays / 7);
  const detection = 1 - blockedShare;
  const anomaly = stats.averageAnomalyScore === null ? 1 - criticalShare : 0.5 * (1 - criticalShare) + 0.5 * clamp(1 - (stats.averageAnomalyScore - 5) / 20);
  const weights: [number, number][] = [
    [spread, 0.15],
    [persistence, 0.15],
    [detection, 0.2],
    [anomaly, 0.1],
    [cleanShare, 0.2],
  ];
  if (normalShare !== null) weights.push([normalShare, 0.2]);
  const totalWeight = weights.reduce((sum, [, weight]) => sum + weight, 0);
  const score = weights.reduce((sum, [value, weight]) => sum + value * weight, 0) / totalWeight;

  const severe = criticalShare >= 0.5 || (stats.averageAnomalyScore ?? 0) >= 15 || blockedShare >= 0.8;
  const pathSignal = stats.paths && stats.paths.length > 0 ? pathSignals(stats.paths) : null;
  const probing = pathSignal !== null && pathSignal.probeShare >= PROBE_SHARE_LIMIT;
  const scattered = attackCritical && pathSignal?.scattered === true;
  let confidence: SuggestionConfidence = score >= HIGH_SCORE && cleanShare >= 0.6 && stats.clients >= 10 ? "high" : score >= MEDIUM_SCORE ? "medium" : "low";
  if (attackCritical && confidence === "high") confidence = "medium";
  if ((attackCritical && severe) || probing || scattered) confidence = "low";

  const reasons = [
    `Matched ${stats.events} time${stats.events === 1 ? "" : "s"} for ${stats.clients} different client${stats.clients === 1 ? "" : "s"} on ${stats.activeDays} day${stats.activeDays === 1 ? "" : "s"}`,
    `${percent(stats.events - stats.blockedEvents, stats.events)}% of the matches did not block the request (detection-only or below the anomaly threshold)`,
    `${stats.cleanClients} of ${stats.clients} clients triggered no other WAF rule`,
  ];
  if (stats.normalClients !== null) {
    reasons.push(`${stats.normalClients} of ${stats.clients} clients also made successful requests to this host`);
  }
  if (stats.averageAnomalyScore !== null) reasons.push(`Average anomaly score when the threshold was exceeded: ${stats.averageAnomalyScore}`);
  if (stats.criticalEvents > 0) reasons.push(`${percent(stats.criticalEvents, stats.events)}% of the matches had critical severity`);
  if (topPrefix && prefixShare >= 0.5) reasons.push(`${percent(topPrefix.events, stats.events)}% of the matches are under ${topPrefix.prefix}`);
  if (pathSignal && pathSignal.probeShare > 0) {
    reasons.push(`${Math.round(pathSignal.probeShare * 100)}% of the matches ask for files a website does not serve (dot-files, backups, system files), which is what scanners look for`);
  }
  if (scattered && pathSignal) {
    reasons.push(`The matches are spread over ${pathSignal.distinctPaths} different paths, like a scanner trying paths, not one endpoint`);
  }
  if (attackCritical) {
    reasons.push(
      `${family?.name} rule: turning it off for the host removes protection against a critical attack class, so this is never a high-confidence suggestion`
    );
  }

  const rounded = Math.round(score * 100);
  const minScore = attackCritical && severe ? SEVERE_ATTACK_MIN_SCORE : MIN_SUGGESTION_SCORE;
  return { suggest: !probing && !scattered && rounded >= minScore, score: rounded, confidence, family: family?.name ?? null, attackCritical, reasons };
}

const CONFIDENCE_ORDER: Record<SuggestionConfidence, number> = { high: 0, medium: 1, low: 2 };

/** Highest confidence first, then by volume (events, then clients). */
export function compareSuggestions(
  a: { confidence: SuggestionConfidence; events: number; clients: number; score: number },
  b: { confidence: SuggestionConfidence; events: number; clients: number; score: number }
): number {
  return (
    CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence] ||
    b.events - a.events ||
    b.clients - a.clients ||
    b.score - a.score
  );
}
