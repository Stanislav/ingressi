/**
 * Helpers for choosing where a WAF exclusion applies: the paths a request's
 * path can be narrowed or widened to, whether it holds an ID (so an exact
 * path would only ever match that one request), the sentence that says what
 * an exclusion covers, and field problems worded for a form. Pure, so the
 * dialog and its tests share it; the rules themselves are in waf-exclusions.ts.
 */
import { normalizeVariable, pathError } from "./waf-exclusions";

export type ExclusionPathMatch = "exact" | "prefix";

/** One way to scope an exclusion by path; `path` null is every path. */
export type PathChoice = { key: string; path: string | null; pathMatch: ExclusionPathMatch | null };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONG_HEX = /^[0-9a-f]{16,}$/i;
const LONG_DIGITS = /^\d{6,}$/;
/** Opaque tokens (ULIDs, nanoids, base64url ids): long, with both letters and digits. */
const OPAQUE_TOKEN = /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_]{20,}$/;

/** True when a path segment looks like an identifier that differs from one request to the next. */
export function looksLikeId(segment: string): boolean {
  return UUID.test(segment) || LONG_HEX.test(segment) || LONG_DIGITS.test(segment) || OPAQUE_TOKEN.test(segment);
}

function segmentsOf(path: string): string[] {
  return path.split("/").filter((segment) => segment !== "");
}

/**
 * The directory above the first ID-like segment: "/Items/" for
 * "/Items/<id>/PlaybackInfo". Null when the path has no ID, or starts with
 * one (nothing above it to fall back to).
 */
export function pathAboveId(path: string): string | null {
  const segments = segmentsOf(path);
  const index = segments.findIndex(looksLikeId);
  return index < 1 ? null : `/${segments.slice(0, index).join("/")}/`;
}

/** The segment `pathAboveId` stopped at, for saying what looks like an ID. */
export function idSegmentOf(path: string): string | null {
  return segmentsOf(path).find(looksLikeId) ?? null;
}

const MAX_DIRECTORIES = 5;

/**
 * The ways to scope by this path, widest first: every path, each directory
 * above it (starts with), and the path itself (exactly).
 */
export function pathChoices(path: string | null): PathChoice[] {
  const choices: PathChoice[] = [{ key: "any", path: null, pathMatch: null }];
  if (!path) return choices;
  const segments = segmentsOf(path);
  let directories = segments.slice(0, -1).map((_, index) => `/${segments.slice(0, index + 1).join("/")}/`);
  // A very deep path: its first directories and its nearest ones.
  if (directories.length > MAX_DIRECTORIES) directories = [...directories.slice(0, 2), ...directories.slice(-(MAX_DIRECTORIES - 2))];
  for (const directory of directories) choices.push({ key: `prefix:${directory}`, path: directory, pathMatch: "prefix" });
  choices.push({ key: "exact", path, pathMatch: "exact" });
  return choices;
}

/** What an exclusion covers, in words: "on Docs, for paths starting with /api/". */
export function describeScope(scope: { hostName: string | null; path: string; pathMatch: ExclusionPathMatch }): string {
  const where = scope.hostName ? `on ${scope.hostName}` : "on every host that follows the global settings";
  const path = scope.path.trim();
  return `${where}, ${!path ? "for every path" : scope.pathMatch === "prefix" ? `for paths starting with ${path}` : `for exactly ${path}`}`;
}

function sentence(message: string): string {
  return message.charAt(0).toUpperCase() + message.slice(1);
}

/** Why the path cannot be used, worded for a form field; null when it is empty (every path) or valid. */
export function pathProblem(path: string): string | null {
  const trimmed = path.trim();
  if (!trimmed) return null;
  const error = pathError(trimmed);
  return error ? error.replace(/^path/, "The path") : null;
}

/** Why the variable cannot be used, worded for a form field; null when it is empty (every variable) or valid. */
export function variableProblem(variable: string): string | null {
  if (!variable.trim()) return null;
  const normalized = normalizeVariable(variable);
  return "error" in normalized ? sentence(normalized.error.replace(/^variable/, "The variable")) : null;
}
