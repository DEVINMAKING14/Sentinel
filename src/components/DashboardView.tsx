import React from 'react';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import { DashboardOverview, ScanResult } from '../types';

interface DashboardViewProps {
  overview: DashboardOverview | null;
  onSelectScan: (scan: ScanResult) => void;
  onStartNewScan: () => void;
  onOpenThreatIntel: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  overview,
  onSelectScan,
  onStartNewScan,
  onOpenThreatIntel,
}) => (
  <div className="mx-auto max-w-7xl space-y-6 p-8">
    <header className="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 className="text-xl font-bold text-[#202522]">Investigation overview</h1>
        <p className="mt-1 text-xs text-[#747C78]">Counts reflect stored investigations and their collected evidence.</p>
      </div>
      <div className="flex gap-2">
        <button onClick={onOpenThreatIntel} className="rounded-xl border border-[#E2E5E1] bg-white px-4 py-2 text-xs font-semibold">
          Community intelligence
        </button>
        <button onClick={onStartNewScan} className="rounded-xl bg-[#202522] px-4 py-2 text-xs font-semibold text-white">
          Investigate a website
        </button>
      </div>
    </header>

    {overview ? (
      <>
        <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            ['Investigations', overview.totalScans],
            ['Open findings', overview.openFindingsCount],
            ['Observed domains', overview.attackSurface.domains],
            ['Observed DNS records', overview.attackSurface.dnsRecords],
          ].map(([label, count]) => (
            <div key={label} className="rounded-2xl border border-[#E2E5E1] bg-white p-5">
              <div className="text-xs text-[#747C78]">{label}</div>
              <div className="mt-2 font-mono text-3xl font-bold text-[#202522]">{count}</div>
            </div>
          ))}
        </section>

        <section className="rounded-2xl border border-[#E2E5E1] bg-white p-5">
          <h2 className="text-sm font-bold text-[#202522]">Recent investigations</h2>
          {overview.recentScans.length === 0 ? (
            <p className="mt-4 text-xs text-[#747C78]">No investigations have been recorded.</p>
          ) : (
            <div className="mt-3 divide-y divide-[#E2E5E1]">
              {overview.recentScans.map(scan => (
                <button
                  key={scan.id}
                  onClick={() => onSelectScan(scan)}
                  className="flex w-full items-center justify-between gap-4 py-3 text-left hover:bg-[#FAFBF9]"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-xs font-semibold text-[#202522]">{scan.domain}</span>
                    <span className="mt-1 block truncate font-mono text-[10px] text-[#747C78]">{scan.submittedUrl || scan.targetUrl}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2 text-xs">
                    <ShieldAlert className="h-3.5 w-3.5 text-[#747C78]" />
                    {scan.riskScore}/100
                    <ArrowRight className="h-3.5 w-3.5 text-[#747C78]" />
                  </span>
                </button>
              ))}
            </div>
          )}
        </section>
      </>
    ) : (
      <p className="rounded-2xl border border-[#E2E5E1] bg-white p-5 text-xs text-[#747C78]">
        Overview data is not available yet.
      </p>
    )}
  </div>
);
