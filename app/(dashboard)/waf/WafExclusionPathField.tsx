"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Banner } from "@/components/ui/Banner";
import { cn } from "@/lib/utils";
import { idSegmentOf, pathAboveId, pathChoices, type ExclusionPathMatch } from "@/src/lib/waf-exclusion-scope";
import { Segmented } from "./Segmented";

/**
 * The path of an exclusion: typed, matched from its start or exactly, or
 * picked from the paths a request's path can be narrowed or widened to. A path
 * with an ID in it says so and offers the directory above it, because an exact
 * path with an ID only ever matches that one request.
 */
export function WafExclusionPathField({
  id,
  path,
  pathMatch,
  onChange,
  requestPath,
  error,
}: {
  id: string;
  path: string;
  pathMatch: ExclusionPathMatch;
  onChange: (path: string, pathMatch: ExclusionPathMatch) => void;
  /** The path the quick picks are made from (the path of the request), when there is one. */
  requestPath: string | null;
  error?: string | null;
}) {
  const trimmed = path.trim();
  const choices = pathChoices(requestPath);
  const above = trimmed ? pathAboveId(trimmed) : null;
  const idSegment = trimmed ? idSegmentOf(trimmed) : null;
  const errorId = `${id}-error`;

  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>
        Path <span className="font-normal text-muted-foreground">(optional)</span>
      </Label>
      <div className="flex flex-wrap gap-2">
        <Input
          id={id}
          className="min-w-0 flex-1 font-mono"
          placeholder="/api/public/"
          value={path}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          onChange={(event) => onChange(event.target.value, pathMatch)}
        />
        <Segmented
          label="Path match"
          value={pathMatch}
          onChange={(value) => onChange(path, value as ExclusionPathMatch)}
          disabled={!trimmed}
          options={[
            { value: "prefix", label: "Starts with" },
            { value: "exact", label: "Exactly" },
          ]}
        />
      </div>
      {choices.length > 1 && (
        <div role="group" aria-label="Paths to choose from" className="flex flex-wrap gap-1.5">
          {choices.map((choice) => {
            const active = choice.path === null ? !trimmed : trimmed === choice.path && pathMatch === choice.pathMatch;
            const label = choice.path ?? "Any path";
            return (
              <button
                key={choice.key}
                type="button"
                aria-pressed={active}
                title={choice.path === null ? "Every path" : `${choice.pathMatch === "prefix" ? "Starts with" : "Exactly"} ${choice.path}`}
                onClick={() => onChange(choice.path ?? "", choice.pathMatch ?? pathMatch)}
                className={cn(
                  "max-w-full truncate rounded-full border px-2.5 py-1 text-xs transition-colors",
                  choice.path !== null && "font-mono",
                  active ? "border-brand bg-brand-tint text-foreground" : "border-line2 text-muted-foreground hover:bg-raise hover:text-foreground"
                )}
              >
                {label}
              </button>
            );
          })}
        </div>
      )}
      {above && idSegment && (
        <Banner
          tone="info"
          className="px-3 py-2.5"
          title="The path has an ID in it, so it matches only that one."
          actions={
            <Button type="button" size="sm" variant="outline" onClick={() => onChange(above, "prefix")}>
              Use <span className="num">{above}</span>
            </Button>
          }
        />
      )}
      {error ? (
        <p id={errorId} role="alert" className="m-0 text-xs text-destructive">
          {error}
        </p>
      ) : (
        <span className="text-xs text-muted-foreground">Without the query string.</span>
      )}
    </div>
  );
}
