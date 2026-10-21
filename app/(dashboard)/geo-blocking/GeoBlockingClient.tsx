"use client";

import { Banner } from "@/components/ui/Banner";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionCard } from "@/components/ui/SectionCard";
import { StatusDot } from "@/components/ui/StatusDot";
import { GeoBlockFields } from "@/components/proxy-hosts/GeoBlockFields";
import type { GeoBlockSettings } from "@/lib/settings";
import type { GeoIpDatabaseView } from "@/src/lib/geoip-status";
import { formatDateTimeUtc } from "@/src/lib/date-format";
import { SettingRow, SettingRows, SettingsForm, SettingsGroupForms } from "@/src/components/settings/settings-form";
import { updateGeoBlockSettingsAction } from "../settings/actions";
import { useUnsavedWarning } from "../settings/use-unsaved-warning";

export type GeoBlockingProps = {
  geoblock: GeoBlockSettings | null;
  /** The GeoLite2 databases on this install. */
  geoip: GeoIpDatabaseView[];
  /** settings:write */
  canSave: boolean;
  /** waf:read, for the breadcrumb's link. */
  canOpenSecurity: boolean;
};

/** Geo blocking for every proxy host, and the GeoLite2 databases it needs. */
export default function GeoBlockingClient({ geoblock, geoip, canSave, canOpenSecurity }: GeoBlockingProps) {
  const onDirtyChange = useUnsavedWarning();
  const missing = geoip.filter((database) => !database.found);
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        className="mb-0"
        breadcrumb={["Observe", canOpenSecurity ? { label: "Security events", href: "/security" } : "Security events", "Geo blocking"]}
        title="Geo blocking"
        description="For every proxy host. A host's own rules are merged with these."
      />
      {missing.length > 0 && (
        <Banner tone="warn">
          {missing.length === geoip.length
            ? "The GeoLite2 databases are missing, so country, continent and network rules do not match."
            : `${missing.map((database) => database.name).join(" and ")} is missing, so the rules that need it do not match.`}{" "}
          Put the MaxMind GeoLite2 databases in the geoip-data volume to make them available (documentation/geo-blocking.md).
        </Banner>
      )}
      <SettingsGroupForms name="Geo blocking" canSave={canSave} onDirtyChange={onDirtyChange}>
        <SectionCard title="Default rules" headingLevel={2} divided={false}>
          <SettingsForm action={updateGeoBlockSettingsAction} className="border-t border-line px-5 py-4">
            <GeoBlockFields initialValues={{ geoblock: geoblock ?? null, geoblock_mode: "merge" }} showModeSelector={false} />
          </SettingsForm>
        </SectionCard>
      </SettingsGroupForms>
      <SectionCard id="geoip" className="scroll-mt-20 md:scroll-mt-4" title="GeoIP databases" headingLevel={2} divided={false}>
        <SettingRows>
          {geoip.map((database) => (
            <SettingRow
              key={database.path}
              label={database.name}
              note={database.updatedAt ? `Updated ${formatDateTimeUtc(database.updatedAt)} UTC` : undefined}
            >
              <span className="flex min-h-9 items-center">
                <StatusDot
                  tone={database.found ? "ok" : "bad"}
                  label={
                    <span className="text-[13px] [overflow-wrap:anywhere]">
                      {database.found ? "Found" : "Missing"} · <span className="num">{database.path}</span>
                    </span>
                  }
                />
              </span>
            </SettingRow>
          ))}
        </SettingRows>
      </SectionCard>
    </div>
  );
}
