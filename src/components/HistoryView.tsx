import React, { useState } from 'react';
import { History, Search, Download, ExternalLink, ShieldCheck, ShieldAlert, ChevronRight, Bookmark } from 'lucide-react';
import { ScanResult } from '../types';

interface HistoryViewProps {
  scans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onRescan: (url: string) => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  scans,
  onSelectScan,
  onRescan,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [onlyWatchlist, setOnlyWatchlist] = useState(false);

  // Read watchlisted IDs
  let watchlistedIds: string[] = [];
  try {
    const raw = localStorage.getItem('sentinel_watchlist');
    if (raw) watchlistedIds = JSON.parse(raw);
  } catch {}

  const filtered = scans.filter((s) => {
    const matchesSearch = s.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.targetUrl.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSev = filterSeverity === 'ALL' || s.riskCategory === filterSeverity;
    const matchesWatchlist = !onlyWatchlist || watchlistedIds.includes(s.id) || watchlistedIds.includes(s.domain);
    return matchesSearch && matchesSev && matchesWatchlist;
  });

  const exportAllHistory = () => {
    const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-audit-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-[0_1px_3px_rgba(0,0,0,0.04)] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <History className="w-5 h-5 text-[#426B57]" />
            <h2 className="text-lg font-bold text-[#202522]">Scan History & Compliance Audit Logs</h2>
          </div>
          <p className="text-xs text-[#747C78]">
            Immutable telemetry records of past security scans, threat vector evaluations, and cryptographic verifications.
          </p>
        </div>

        <button
          onClick={exportAllHistory}
          className="px-4 py-2 bg-[#F7F7F4] hover:bg-[#EAECE8] border border-[#E2E5E1] text-[#202522] rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors self-start sm:self-auto"
        >
          <Download className="w-4 h-4" />
          <span>Export Audit History</span>
        </button>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-[#747C78]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search audit records by domain or URL..."
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-[#E2E5E1] rounded-xl text-xs font-mono text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setOnlyWatchlist(!onlyWatchlist)}
            className={`px-3 py-2 text-xs font-semibold rounded-xl flex items-center gap-1.5 transition-all ${
              onlyWatchlist
                ? 'bg-[#2E7D52] text-white shadow-xs'
                : 'bg-white border border-[#E2E5E1] text-[#555C57] hover:text-[#202522]'
            }`}
          >
            <Bookmark className="w-3.5 h-3.5" />
            <span>Watchlist ({watchlistedIds.length})</span>
          </button>

          <div className="w-[1px] h-6 bg-[#E2E5E1] mx-1" />

          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'SAFE'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterSeverity(lvl)}
              className={`px-3 py-2 text-xs font-medium rounded-xl transition-all ${
                filterSeverity === lvl
                  ? 'bg-[#202522] text-white'
                  : 'bg-white border border-[#E2E5E1] text-[#555C57] hover:text-[#202522]'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Scans Table */}
      <div className="bg-white border border-[#E2E5E1] rounded-2xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#E2E5E1] bg-[#F7F7F4] text-[#747C78] font-semibold">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Target Hostname</th>
                <th className="py-3 px-4">Risk Classification</th>
                <th className="py-3 px-4 text-right">Risk Score</th>
                <th className="py-3 px-4">Findings Count</th>
                <th className="py-3 px-4">Execution Time</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-100 font-mono">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs text-[#747C78] font-sans">
                    No scan records found matching filter criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => onSelectScan(s)}
                    className="hover:bg-neutral-50/80 cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 text-[#747C78] text-[11px]">
                      {new Date(s.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-[#202522]">
                      <div className="truncate max-w-xs">{s.domain}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${
                        s.riskCategory === 'CRITICAL' ? 'bg-[#B42318]/10 text-[#B42318]' :
                        s.riskCategory === 'HIGH' ? 'bg-[#D97706]/10 text-[#D97706]' :
                        s.riskCategory === 'MEDIUM' ? 'bg-amber-100 text-amber-900' :
                        'bg-[#39805B]/10 text-[#39805B]'
                      }`}>
                        {s.riskCategory}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right font-bold tabular-nums">
                      <span className={s.riskScore >= 75 ? 'text-[#B42318]' : s.riskScore >= 50 ? 'text-[#D97706]' : 'text-[#39805B]'}>
                        {s.riskScore}/100
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-sans text-[#555C57]">
                      {s.findings.length} findings
                    </td>
                    <td className="py-3.5 px-4 text-[#747C78] text-[11px]">
                      {s.scanDurationMs}ms
                    </td>
                    <td className="py-3.5 px-4 text-right font-sans" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onRescan(s.targetUrl)}
                          className="px-2.5 py-1 bg-[#F7F7F4] hover:bg-[#EAECE8] border border-[#E2E5E1] rounded-lg text-xs font-semibold text-[#202522] transition-colors"
                        >
                          Re-scan
                        </button>
                        <button
                          onClick={() => onSelectScan(s)}
                          className="px-2.5 py-1 bg-[#202522] hover:bg-[#323935] text-white rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors"
                        >
                          <span>Report</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
