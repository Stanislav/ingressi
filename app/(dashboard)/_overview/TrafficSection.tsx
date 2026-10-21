"use client";

import { KpiTile } from "@/components/ui/KpiTile";
import { SectionCard } from "@/components/ui/SectionCard";
import { EmptyState } from "@/components/ui/EmptyState";
import { Banner } from "@/components/ui/Banner";
import { StackedAreaChart } from "@/components/ui/StackedAreaChart";
import { formatBytes, formatChange } from "@/components/ui/chart-format";
import { useFormat } from "@/src/components/preferences/PreferencesProvider";
import { analyticsHref, securityHref } from "@/src/lib/analytics/links";
import { OVERVIEW_RANGE_LABELS, type OverviewRange, type OverviewTraffic } from "@/src/lib/overview-shared";
import { ChartColumn } from "lucide-react";
import { bucketLabel, momentLabel, PREVIOUS_PERIOD, zoneLabel } from "./format";

/** Exact counts up to 100,000, then compact ("1.2M"), in the viewer's number format. */
function useCount() {
  const fmt = useFormat();
  return (value: number) =>
    Math.abs(value) < 100_000 ? fmt.number(Math.round(value)) : fmt.number(value, { notation: "compact", maximumFractionDigits: 1 });
}

function ratePercent(fmt: ReturnType<typeof useFormat>, value: number): string {
  return fmt.percent(value, value > 0 && value < 0.01 ? 2 : 1);
}

/** The four headline tiles: requests, mitigated with its share, the 5xx rate and bandwidth. */
export function KpiRow({ traffic, range }: { traffic: OverviewTraffic; range: OverviewRange }) {
  const fmt = useFormat();
  const count = useCount();
  const { totals, previous, sparklines } = traffic;
  const versus = `vs ${PREVIOUS_PERIOD[range] ?? "previous period"}`;
  const peak = traffic.peakMitigated;
  const peakTime = peak ? momentLabel(peak.ts * 1000, traffic.range.step, fmt.timeZone) : null;
  const href = analyticsHref([], range);
  // Phone: two columns, no sparklines, each tile opens the analytics (Phone.dc.html).
  const tile = "max-md:px-3.5 max-md:py-3 max-md:[&_svg]:hidden";
  return (
    <div className="grid grid-cols-2 gap-2.5 md:grid-cols-[repeat(auto-fit,minmax(min(220px,100%),1fr))] md:gap-3" data-testid="overview-kpis">
      <KpiTile
        label="Requests"
        value={count(totals.requests)}
        color="var(--served)"
        sparkline={sparklines.requests}
        delta={previous ? formatChange(totals.requests, previous.requests, null) : undefined}
        note={previous ? versus : "no earlier period to compare"}
        href={href}
        className={tile}
      />
      <KpiTile
        label="Mitigated"
        value={count(totals.mitigated)}
        color="var(--waf)"
        sparkline={sparklines.mitigated}
        delta={{ text: ratePercent(fmt, totals.mitigatedShare), tone: "neutral" }}
        note={peakTime ? `of requests · peak at ${peakTime}` : "of requests"}
        href={href}
        className={tile}
      />
      <KpiTile
        label="5xx error rate"
        value={ratePercent(fmt, totals.errorRate5xx)}
        color="var(--err5)"
        sparkline={sparklines.errors5xx}
        delta={{
          text: `${fmt.number(totals.errors5xx)} ${totals.errors5xx === 1 ? "response" : "responses"}`,
          tone: totals.errorRate5xx >= 0.01 ? "bad" : "neutral",
        }}
        note={traffic.topErrorHost && traffic.topErrorHost.count > 0 ? `${fmt.number(traffic.topErrorHost.count)} from ${traffic.topErrorHost.name}` : undefined}
        href={href}
        className={tile}
      />
      <KpiTile
        label="Bandwidth"
        value={formatBytes(totals.bytes)}
        color="var(--served2)"
        sparkline={sparklines.bytes}
        delta={previous ? formatChange(totals.bytes, previous.bytes, null) : undefined}
        note={previous ? versus : "no earlier period to compare"}
        href={href}
        className={tile}
      />
    </div>
  );
}

/** "30 minutes", "3 hours", "minute", "day": a bucket's width in the chart's accessible name. */
function stepText(seconds: number): string {
  if (seconds % 86_400 === 0) return seconds === 86_400 ? "day" : `${seconds / 86_400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? "hour" : `${seconds / 3600} hours`;
  if (seconds % 60 === 0) return seconds === 60 ? "minute" : `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

function Swatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-[13px] text-muted-foreground max-md:text-xs">
      <span aria-hidden="true" className="size-2.5 rounded-[3px] max-md:size-2 max-md:rounded-[2px]" style={{ background: color }} />
      {label}
    </span>
  );
}

/** Served and mitigated requests over the range, with the busiest moment of mitigation marked. */
export function TrafficChart({
  traffic,
  range,
  security,
  compact = false,
}: {
  traffic: OverviewTraffic;
  range: OverviewRange;
  /** The viewer may open the security events: the peak's pill leads to that moment's. */
  security: boolean;
  /** The first-run page's smaller chart. */
  compact?: boolean;
}) {
  const fmt = useFormat();
  const count = useCount();
  const { step, start, buckets: n } = traffic.range;
  const buckets = Array.from({ length: n }, (_, i) => (start + i * step) * 1000);
  const peak = traffic.peakMitigated;
  const rangeLabel = OVERVIEW_RANGE_LABELS[range];
  const stepLabel = stepText(step);
  const zone = zoneLabel(start * 1000, fmt.timeZone);
  return (
    <SectionCard
      title={compact ? `Traffic, ${rangeLabel}` : <><span className="md:hidden">Traffic</span><span className="max-md:hidden">Traffic, {rangeLabel}</span></>}
      divided={false}
      padded
      className="relative max-md:[&>div:first-child]:px-3.5 max-md:[&>div:first-child]:py-1"
      contentClassName="pt-0 max-md:px-3.5 max-md:pb-3"
      actions={
        <span className="flex items-center gap-3 max-md:gap-2">
          <Swatch color="var(--served)" label="Served" />
          <Swatch color="var(--waf)" label="Mitigated" />
        </span>
      }
      link={compact ? undefined : { label: "Open analytics", href: analyticsHref([], range) }}
    >
      <StackedAreaChart
        title={`Requests per ${stepLabel} over the ${rangeLabel}, served and mitigated`}
        buckets={buckets}
        stepSeconds={step}
        series={[
          { key: "served", label: "Served", color: "var(--served)", values: traffic.served, fillOpacity: 0.22 },
          { key: "mitigated", label: "Mitigated", color: "var(--waf)", values: traffic.mitigated, fillOpacity: 0.55 },
        ]}
        annotations={
          peak
            ? [
                {
                  index: peak.index,
                  label: `Peak ${momentLabel(peak.ts * 1000, step, fmt.timeZone)} · ${count(peak.value)} mitigated`,
                  color: "var(--waf)",
                  href: security ? securityHref({ range: { from: peak.ts, to: peak.ts + step } }) : undefined,
                },
              ]
            : []
        }
        legend={false}
        height={compact ? 168 : 200}
        xTicks={5}
        formatValue={(value) => count(value)}
        formatBucket={(ms, long) => bucketLabel(ms, step, long, fmt.timeZone)}
        bucketHeader={`Time (${zone})`}
        emptyText={`No requests in the ${rangeLabel}.`}
        className="max-md:[&_[data-testid=chart-plot]]:h-[96px]!"
      />
    </SectionCard>
  );
}

/** What the traffic area shows when there is no traffic to chart: analytics off or ClickHouse not answering. */
export function TrafficUnavailable({ status }: { status: "disabled" | "unavailable" }) {
  if (status === "unavailable") {
    return (
      <Banner tone="warn" title="Traffic could not be read.">
        ClickHouse did not answer.
      </Banner>
    );
  }
  return (
    <SectionCard title="Traffic" divided={false} id="traffic">
      <EmptyState
        compact
        icon={ChartColumn}
        title="Analytics are off"
        description={
          <>
            Set a <span className="num">CLICKHOUSE_PASSWORD</span> in <span className="num">.env</span>, then run{" "}
            <span className="num">docker compose up -d</span>.
          </>
        }
        className="px-[18px] pt-0"
      />
    </SectionCard>
  );
}
