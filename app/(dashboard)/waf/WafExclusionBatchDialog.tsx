"use client";

import { useEffect, useState, useTransition } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Banner } from "@/components/ui/Banner";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { WafExclusionSuggestionView } from "@/src/lib/waf-event-explain";
import { describeScope, pathProblem, variableProblem, type ExclusionPathMatch } from "@/src/lib/waf-exclusion-scope";
import { createWafExclusionsAction } from "./actions";
import { Segmented } from "./Segmented";
import { WafExclusionPathField } from "./WafExclusionPathField";

/** Where the suggested exclusions apply, in words: "on Langfuse, for requests to /api/x". */
export function suggestionScope(suggestion: Pick<WafExclusionSuggestionView, "hostName" | "path">): string {
  const where = suggestion.hostName ? `on ${suggestion.hostName}` : "on every host that follows the global settings";
  return `${where}, ${suggestion.path ? `for requests to ${suggestion.path}` : "for every request"}`;
}

/**
 * The exclusions a WAF event suggests, reviewed and changed together: one per
 * rule that added to the score, starting as narrow as the record allows (the
 * host, the exact path, the variable it matched). The host and path are shared
 * by the rules (all from one request) and can be widened; each rule's variable
 * can be changed or cleared. Untick the rules to keep; the rest are added with
 * one reason and one apply (createWafExclusionsAction, waf:write).
 */
export function WafExclusionBatchDialog({
  open,
  onOpenChange,
  suggestions,
  ruleMessages,
  defaultReason,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  suggestions: readonly WafExclusionSuggestionView[];
  /** What each rule checks, by rule id. */
  ruleMessages: ReadonlyMap<number, string>;
  defaultReason: string;
  onCreated?: () => void;
}) {
  const [chosen, setChosen] = useState<ReadonlySet<number>>(() => new Set());
  const [variables, setVariables] = useState<string[]>([]);
  const [path, setPath] = useState("");
  const [pathMatch, setPathMatch] = useState<ExclusionPathMatch>("exact");
  const [everyHost, setEveryHost] = useState(false);
  const [reason, setReason] = useState(defaultReason);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [pending, startTransition] = useTransition();

  // The request all the suggestions come from: its host and path.
  const request = suggestions[0];
  const requestPath = request?.path ?? null;
  const hostName = request?.hostName ?? null;
  const canPickHost = request?.proxyHostId != null;

  useEffect(() => {
    if (!open) return;
    setChosen(new Set(suggestions.map((_, index) => index)));
    setVariables(suggestions.map((suggestion) => suggestion.variable ?? ""));
    setPath(suggestions[0]?.path ?? "");
    setPathMatch(suggestions[0]?.pathMatch ?? "exact");
    setEveryHost(suggestions[0]?.proxyHostId == null);
    setReason(defaultReason);
    setError(null);
    setSubmitted(false);
  }, [open, suggestions, defaultReason]);

  const count = chosen.size;
  const trimmedPath = path.trim();
  const pathIssue = pathProblem(path);
  const variableIssues = suggestions.map((_, index) => (chosen.has(index) ? variableProblem(variables[index] ?? "") : null));
  const reasonIssue = reason.trim() ? null : "Say why, so others know when the exclusion can go.";
  const scopeHost = everyHost ? null : hostName;
  const picked = suggestions.map((suggestion, index) => ({ suggestion, index })).filter(({ index }) => chosen.has(index));
  // A rule with neither a path nor a variable is off for every request in its scope.
  const wide = picked.filter(({ index }) => !trimmedPath && !(variables[index] ?? "").trim()).map(({ suggestion }) => suggestion.ruleId);
  const limited = picked.some(({ index }) => (variables[index] ?? "").trim());

  function setVariable(index: number, value: string) {
    setVariables((current) => current.map((entry, i) => (i === index ? value : entry)));
  }

  function submit() {
    setSubmitted(true);
    if (count === 0) {
      setError("Choose at least one rule.");
      return;
    }
    setError(null);
    // The fields that are wrong say so, next to them.
    if (pathIssue || variableIssues.some(Boolean) || reasonIssue) return;
    startTransition(async () => {
      const result = await createWafExclusionsAction(
        picked.map(({ suggestion, index }) => ({
          ruleId: suggestion.ruleId,
          proxyHostId: everyHost ? null : suggestion.proxyHostId,
          path: trimmedPath || null,
          pathMatch: trimmedPath ? pathMatch : null,
          variable: (variables[index] ?? "").trim() || null,
          reason: reason.trim(),
        }))
      );
      if (!result.ok) {
        setError(result.error);
        return;
      }
      toast.success(result.message ?? "Rules excluded.");
      onOpenChange(false);
      onCreated?.();
    });
  }

  return (
    <Dialog open={open} onOpenChange={(value) => !pending && onOpenChange(value)}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Exclude {suggestions.length === 1 ? `rule ${suggestions[0].ruleId}` : `${suggestions.length} rules`}</DialogTitle>
          <DialogDescription>Skip {suggestions.length === 1 ? "it" : "them"} only where {suggestions.length === 1 ? "it is" : "they are"} a false positive. Every other rule still checks these requests.</DialogDescription>
        </DialogHeader>
        <form
          className="flex min-h-0 flex-1 flex-col gap-4"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto py-0.5 pl-0.5 pr-3 [scrollbar-gutter:stable]">
            <fieldset className="m-0 flex min-w-0 flex-col gap-0 rounded-[10px] border border-line p-0">
              <legend className="sr-only">Rules to exclude</legend>
              <ul className="m-0 max-h-[34vh] list-none overflow-y-auto p-0">
                {suggestions.map((suggestion, index) => {
                  const id = `waf-batch-${index}`;
                  const ticked = chosen.has(index);
                  const issue = submitted ? variableIssues[index] : null;
                  const suggested = suggestion.variable ?? "";
                  return (
                    <li key={`${suggestion.ruleId}-${suggestion.variable ?? ""}-${index}`} className="flex flex-col gap-2 border-b border-line px-3 py-2.5 last:border-b-0">
                      <div className="flex items-start gap-3">
                        {suggestions.length > 1 && (
                          <Checkbox
                            id={id}
                            className="mt-0.5"
                            checked={ticked}
                            onCheckedChange={(checked) =>
                              setChosen((current) => {
                                const next = new Set(current);
                                if (checked === true) next.add(index);
                                else next.delete(index);
                                return next;
                              })
                            }
                          />
                        )}
                        <label htmlFor={suggestions.length > 1 ? id : undefined} className={suggestions.length > 1 ? "min-w-0 flex-1 cursor-pointer text-[13px] [overflow-wrap:anywhere]" : "min-w-0 flex-1 text-[13px] [overflow-wrap:anywhere]"}>
                          <span className="num text-muted-foreground">{suggestion.ruleId}</span> {ruleMessages.get(suggestion.ruleId) ?? "Core Rule Set rule"}
                        </label>
                      </div>
                      <div className={suggestions.length > 1 ? "flex flex-col gap-1 pl-7" : "flex flex-col gap-1"}>
                        <div className="flex flex-wrap items-center gap-2">
                          <Label htmlFor={`${id}-variable`} className="shrink-0 text-xs font-normal text-muted-foreground">
                            Variable
                          </Label>
                          <Input
                            id={`${id}-variable`}
                            className="h-8 min-w-0 flex-1 font-mono text-xs"
                            placeholder="Any variable"
                            value={variables[index] ?? ""}
                            disabled={!ticked}
                            autoComplete="off"
                            spellCheck={false}
                            aria-label={`Variable of rule ${suggestion.ruleId}`}
                            aria-invalid={issue ? true : undefined}
                            onChange={(event) => setVariable(index, event.target.value)}
                          />
                          {suggested && (variables[index] ?? "") !== suggested && ticked && (
                            <button type="button" className="text-xs text-brand underline-offset-4 hover:underline" onClick={() => setVariable(index, suggested)}>
                              Use <span className="num">{suggested}</span>
                            </button>
                          )}
                        </div>
                        {issue && (
                          <p role="alert" className="m-0 text-xs text-destructive">
                            {issue}
                          </p>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </fieldset>

            <div className="flex flex-col gap-4">
              {canPickHost ? (
                <div className="flex flex-col gap-1.5">
                  <span id="waf-batch-host-label" className="text-sm font-medium leading-none">
                    Host
                  </span>
                  <Segmented
                    labelledBy="waf-batch-host-label"
                    value={everyHost ? "every" : "host"}
                    onChange={(value) => setEveryHost(value === "every")}
                    options={[
                      { value: "host", label: hostName ?? "This host" },
                      { value: "every", label: "Every host" },
                    ]}
                  />
                  {everyHost && <span className="text-xs text-muted-foreground">Every host that follows the global settings.</span>}
                </div>
              ) : (
                <div className="flex flex-col gap-1.5">
                  <span className="text-sm font-medium leading-none">Host</span>
                  <p className="m-0 text-[13px]">Every host that follows the global settings</p>
                </div>
              )}
              <WafExclusionPathField
                id="waf-batch-path"
                path={path}
                pathMatch={pathMatch}
                onChange={(nextPath, nextMatch) => {
                  setPath(nextPath);
                  setPathMatch(nextMatch);
                }}
                requestPath={requestPath}
                error={submitted ? pathIssue : null}
              />
            </div>

            {wide.length > 0 ? (
              <Banner tone="warn" className="px-3 py-2.5">
                Without a path or a variable, {wide.length === 1 ? "rule" : "rules"} <span className="num">{wide.join(", ")}</span> {wide.length === 1 ? "is" : "are"} off for every request{" "}
                {scopeHost ? `on ${scopeHost}` : "on every host that follows the global settings"}.
              </Banner>
            ) : (
              count > 0 && (
                <p className="m-0 text-[13px] text-muted-foreground [overflow-wrap:anywhere]">
                  Skipped {describeScope({ hostName: scopeHost, path, pathMatch })}.{limited ? ` ${count === 1 ? "The rule is" : "Each rule is"} also limited to its variable.` : ""}
                </p>
              )
            )}

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="waf-batch-reason">Reason</Label>
              <Textarea
                id="waf-batch-reason"
                rows={2}
                maxLength={500}
                value={reason}
                aria-invalid={submitted && reasonIssue ? true : undefined}
                onChange={(event) => setReason(event.target.value.replace(/\n/g, " "))}
              />
              {submitted && reasonIssue && (
                <p role="alert" className="m-0 text-xs text-destructive">
                  {reasonIssue}
                </p>
              )}
            </div>
            {error && (
              <p role="alert" className="m-0 text-sm text-destructive">
                {error}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending || count === 0}>
              {pending ? "Adding…" : count === 1 ? "Add 1 exclusion" : `Add ${count} exclusions`}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
