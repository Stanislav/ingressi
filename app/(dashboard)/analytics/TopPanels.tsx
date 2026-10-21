"use client";

/**
 * The top dimensions under the chart: one TopList per dimension with Only / Exclude
 * to add a filter, mitigated-share tags, the status class bar, "View all"
 * (a dialog with up to 100 rows) and, on the countries panel, the world map.
 */
import { useEffect, useState, type ReactNode } from "react";
import dynamic from "next/dynamic";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { Skeleton } from "@/components/ui/skeleton";
import { TopList, type TopListRow, type TopListSegment } from "@/components/ui/TopList";
import { formatCount } from "@/components/ui/chart-format";
import type { Dimension, FilterOp, TopDimension, TopRow } from "@/src/lib/analytics";
import { asnLabel, countryName, DIMENSION_LABEL, STATUS_CLASS_COLOR, statusColor } from "./present";
import { fetchJson, isTopResult } from "./use-analytics-data";
import type { CountryStats } from "./WorldMapInner";

const WorldMap = dynamic(() => import("./WorldMapInner"), {
  ssr: false,
  loading: () => <Skeleton className="h-[300px] w-full rounded-lg" />,
});

type PanelSpec = {
  dim: Dimension;
  title: string;
  /** "View all 2,400 paths". */
  noun: string;
  mono?: boolean;
  /** Shown only when it has rows. */
  optional?: boolean;
};

export const PANELS: readonly PanelSpec[] = [
  { dim: "host", title: "Hosts", noun: "hosts" },
  { dim: "path", title: "Paths", noun: "paths", mono: true },
  { dim: "country", title: "Countries", noun: "countries" },
  { dim: "asn", title: "Source networks", noun: "networks" },
  { dim: "status", title: "Status codes", noun: "codes", mono: true },
  { dim: "ip", title: "Source IPs", noun: "addresses", mono: true },
  { dim: "user_agent", title: "User agents", noun: "agents" },
  { dim: "method", title: "Methods", noun: "methods", mono: true },
  { dim: "protocol", title: "HTTP versions", noun: "versions", mono: true },
  { dim: "waf_rule", title: "WAF rules", noun: "rules", mono: true, optional: true },
];

/** Rows with at least this share of their requests mitigated get a tag. */
const MITIGATED_TAG_SHARE = 0.05;
const VIEW_ALL_LIMIT = 100;

/** "16% mitigated" for a row whose requests were often stopped. */
export function mitigatedTag(row: Pick<TopRow, "mitigated" | "mitigatedShare">): string | undefined {
  if (row.mitigated <= 0 || row.mitigatedShare < MITIGATED_TAG_SHARE) return undefined;
  return `${Math.round(row.mitigatedShare * 100)}% mitigated`;
}

/** A top row as a TopList row: labels, codes, dots and subtitles per dimension; `value` is what a filter uses. */
export function toListRow(dim: Dimension, row: TopRow): TopListRow {
  const base = { key: `${dim}:${row.value}`, count: row.count, tag: mitigatedTag(row) };
  switch (dim) {
    case "country":
      return { ...base, label: countryName(row.value), code: row.value, value: row.value };
    case "asn":
      return { ...base, label: asnLabel(row.value), sub: row.label ?? undefined, value: row.value === "0" ? "0" : `AS${row.value}` };
    case "status":
      return { ...base, label: row.value, dot: statusColor(row.value), value: row.value };
    case "ip": {
      const where = [row.country, row.asOrg].filter(Boolean).join(" · ");
      return { ...base, label: row.value, sub: where || undefined, value: row.value };
    }
    case "waf_rule":
      return { ...base, label: row.value, sub: row.label ?? undefined, value: row.value };
    default:
      return { ...base, label: row.value === "" ? "(empty)" : row.value, value: row.value };
  }
}

/** The status class share bar. */
export function statusSegments(top: TopDimension | undefined): TopListSegment[] | undefined {
  if (!top?.classes || top.classes.length === 0) return undefined;
  return top.classes.map((c) => ({ label: c.class, fraction: c.share, color: STATUS_CLASS_COLOR[c.class] ?? STATUS_CLASS_COLOR.other }));
}

/** Only the "unknown" value (no GeoIP database): the panel explains instead of listing it. */
function onlyUnknown(dim: Dimension, rows: readonly TopRow[]): boolean {
  if (rows.length !== 1) return false;
  return (dim === "asn" && rows[0].value === "0") || (dim === "country" && rows[0].value === "XX");
}

const UNKNOWN_TEXT: Partial<Record<Dimension, string>> = {
  asn: "No network is known for these requests. The GeoLite2-ASN database in the geoip-data volume adds it.",
  country: "No country is known for these requests. The GeoLite2-Country database in the geoip-data volume adds it.",
};

type FilterHandler = (dim: Dimension, op: FilterOp, value: string) => void;

function Panel({
  spec,
  top,
  total,
  loading,
  failed,
  onFilter,
  onViewAll,
  headerExtra,
  children,
}: {
  spec: PanelSpec;
  top: TopDimension | undefined;
  total: number;
  loading: boolean;
  /** The top lists could not be loaded. */
  failed: boolean;
  onFilter: FilterHandler;
  onViewAll: () => void;
  headerExtra?: ReactNode;
  children?: ReactNode;
}) {
  const rows = top?.rows ?? [];
  const unknown = onlyUnknown(spec.dim, rows);
  const listRows = unknown ? [] : rows.map((row) => toListRow(spec.dim, row));
  const distinct = top?.distinct ?? 0;
  const label = DIMENSION_LABEL[spec.dim];
  return (
    <section aria-label={spec.title} className="flex min-w-0 flex-col rounded-xl border border-line bg-panel" data-panel={spec.dim}>
      <div className="flex items-center gap-2 px-3.5 pb-2 pt-3">
        <h3 className="m-0 flex-1 text-sm font-semibold">{spec.title}</h3>
        {headerExtra}
        <span className="text-xs text-soft">Requests</span>
      </div>
      {children ??
        (loading && !top ? (
          <div className="flex flex-col gap-2 px-3.5 pb-4 pt-1" aria-hidden="true">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-6 w-full" />
            ))}
          </div>
        ) : (
          <TopList
            framed={false}
            dimension={label}
            rows={listRows}
            total={total}
            mono={spec.mono}
            segments={spec.dim === "status" ? statusSegments(top) : undefined}
            emptyText={failed ? "This list could not be loaded." : unknown ? UNKNOWN_TEXT[spec.dim] : "Nothing matches the filters."}
            onInclude={(row) => onFilter(spec.dim, "is", row.value ?? row.label)}
            onExclude={(row) => onFilter(spec.dim, "is_not", row.value ?? row.label)}
          />
        ))}
      {!children && distinct > listRows.length && listRows.length > 0 && (
        <div className="mt-auto border-t border-line px-3.5 pb-2.5 pt-2">
          <button type="button" onClick={onViewAll} className="text-[13px] text-brand hover:text-foreground">
            View all {formatCount(distinct)} {spec.noun}
          </button>
        </div>
      )}
    </section>
  );
}

/** Up to 100 rows of one dimension, loaded when a dialog or the map needs them. */
function useLongList(dim: Dimension | null, listKey: string) {
  const [state, setState] = useState<{ key: string; data: TopDimension | null; total: number; error: string | null } | null>(null);
  const key = dim ? `${listKey}&dimensions=${dim}&limit=${VIEW_ALL_LIMIT}` : null;
  useEffect(() => {
    if (!key) return;
    const controller = new AbortController();
    fetchJson(`/api/v1/analytics/top?${key}`, controller.signal)
      .then((body) => {
        if (!isTopResult(body)) throw new Error("The analytics API sent an answer this page does not understand");
        if (!controller.signal.aborted) setState({ key, data: body.dimensions[0] ?? null, total: body.total, error: null });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ key, data: null, total: 0, error: error instanceof Error ? error.message : "Could not load the list" });
      });
    return () => controller.abort();
  }, [key]);
  return state && state.key === key ? state : null;
}

function ViewAllDialog({
  spec,
  listKey,
  onClose,
  onFilter,
}: {
  spec: PanelSpec | null;
  listKey: string;
  onClose: () => void;
  onFilter: FilterHandler;
}) {
  const list = useLongList(spec?.dim ?? null, listKey);
  const rows = spec && list?.data ? list.data.rows.map((row) => toListRow(spec.dim, row)) : [];
  return (
    <Dialog open={spec !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{spec?.title ?? ""}</DialogTitle>
          <DialogDescription>
            {list?.data
              ? list.data.distinct > rows.length
                ? `The ${formatCount(rows.length)} busiest of about ${formatCount(list.data.distinct)} ${spec?.noun ?? ""}.`
                : `All ${formatCount(rows.length)} ${spec?.noun ?? ""} in this period.`
              : "Loading…"}
          </DialogDescription>
        </DialogHeader>
        <div className="-mx-2 min-h-0 flex-1 overflow-y-auto">
          {list?.error ? (
            <p role="alert" className="m-0 px-2 text-[13px] text-bad">
              {list.error}
            </p>
          ) : !list ? (
            <div className="flex flex-col gap-2 px-2" aria-hidden="true">
              {Array.from({ length: 8 }, (_, i) => (
                <Skeleton key={i} className="h-6 w-full" />
              ))}
            </div>
          ) : (
            spec && (
              <TopList
                framed={false}
                dimension={DIMENSION_LABEL[spec.dim]}
                rows={rows}
                total={list.total}
                mono={spec.mono}
                onInclude={(row) => {
                  onFilter(spec.dim, "is", row.value ?? row.label);
                  onClose();
                }}
                onExclude={(row) => {
                  onFilter(spec.dim, "is_not", row.value ?? row.label);
                  onClose();
                }}
              />
            )
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function CountryMap({ listKey }: { listKey: string }) {
  const list = useLongList("country", listKey);
  if (list?.error) {
    return (
      <p role="alert" className="m-0 px-3.5 pb-4 text-[13px] text-bad">
        {list.error}
      </p>
    );
  }
  if (!list) return <Skeleton className="mx-3.5 mb-3.5 h-[300px] rounded-lg" />;
  const data: CountryStats[] = (list.data?.rows ?? []).map((row) => ({ countryCode: row.value, total: row.count, blocked: row.mitigated }));
  return (
    <div className="px-3.5 pb-3.5">
      <WorldMap data={data} />
    </div>
  );
}

export function TopPanels({
  dimensions,
  total,
  loading,
  failed = false,
  listKey,
  onFilter,
}: {
  dimensions: readonly TopDimension[] | null;
  total: number;
  loading: boolean;
  /** The top lists could not be loaded. */
  failed?: boolean;
  /** Query string of /top (range and filters). */
  listKey: string;
  onFilter: FilterHandler;
}) {
  const [viewAll, setViewAll] = useState<PanelSpec | null>(null);
  const [countryMode, setCountryMode] = useState<"list" | "map">("list");
  const byDim = new Map((dimensions ?? []).map((d) => [d.dimension, d]));

  return (
    <>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-3">
        {PANELS.filter((spec) => !spec.optional || (byDim.get(spec.dim)?.rows.length ?? 0) > 0).map((spec) => (
          <Panel
            key={spec.dim}
            spec={spec}
            top={byDim.get(spec.dim)}
            total={total}
            loading={loading}
            failed={failed}
            onFilter={onFilter}
            onViewAll={() => setViewAll(spec)}
            headerExtra={
              spec.dim === "country" ? (
                <SegmentedControl
                  size="sm"
                  label="Show countries as"
                  value={countryMode}
                  onChange={setCountryMode}
                  options={[
                    { value: "list", label: "List" },
                    { value: "map", label: "Map" },
                  ]}
                />
              ) : undefined
            }
          >
            {spec.dim === "country" && countryMode === "map" ? <CountryMap listKey={listKey} /> : undefined}
          </Panel>
        ))}
      </div>
      <ViewAllDialog spec={viewAll} listKey={listKey} onClose={() => setViewAll(null)} onFilter={onFilter} />
    </>
  );
}
