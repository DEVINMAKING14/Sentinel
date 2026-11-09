import React, { useState } from 'react';
import { 
  Radio, 
  Search, 
  Filter, 
  ThumbsUp, 
  ThumbsDown, 
  Plus, 
  Download, 
  ShieldCheck, 
  AlertOctagon, 
  ExternalLink,
  Tag
} from 'lucide-react';
import { ThreatReport } from '../types';

interface ThreatIntelViewProps {
  reports: ThreatReport[];
  onOpenReportModal: () => void;
  onVerifyReport: (reportId: string, isAffirmative: boolean) => Promise<void>;
  onScanUrl: (url: string) => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  reports,
  onOpenReportModal,
  onVerifyReport,
  onScanUrl,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');

  const filteredReports = reports.filter((r) => {
    const matchesSearch = 
      r.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.targetedBrand && r.targetedBrand.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesType = filterType === 'ALL' || r.threatType === filterType;
    return matchesSearch && matchesType;
  });

  const exportIocsCsv = () => {
    const headers = ['ID', 'Domain', 'URL', 'Threat Type', 'Targeted Brand', 'Reputation', 'Status', 'Submitted At'];
    const rows = filteredReports.map(r => [
      r.id,
      r.domain,
      `"${r.url}"`,
      r.threatType,
      r.targetedBrand || 'N/A',
      r.reputationScore,
      r.status,
      r.submittedAt
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-iocs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-5 h-5 text-[#426B57]" />
            <h2 className="text-lg font-bold text-[#202522]">Collaborative Threat Intelligence Exchange</h2>
          </div>
          <p className="text-xs text-[#747C78]">
            Community verified Indicators of Compromise (IoCs), adversary campaign tracking, and peer reputation scoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={exportIocsCsv}
            className="px-3.5 py-2 bg-[#F7F7F4] hover:bg-[#EAECE8] border border-[#E2E5E1] text-[#202522] rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={onOpenReportModal}
            className="px-4 py-2 bg-[#202522] hover:bg-[#323935] text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4 stroke-[2.5]" />
            <span>Submit Threat Evidence</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-[#747C78]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by domain, URL, or targeted brand (e.g., paypal, login-portal)..."
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-[#E2E5E1] rounded-xl text-xs font-mono text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
          />
        </div>

        <div className="flex items-center gap-2">
          {['ALL', 'PHISHING', 'BRAND_IMPERSONATION', 'PAYMENT_FRAUD', 'CREDENTIAL_HARVESTING'].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-2 text-xs font-medium rounded-xl transition-all whitespace-nowrap ${
                filterType === type
                  ? 'bg-[#202522] text-white'
                  : 'bg-white border border-[#E2E5E1] text-[#555C57] hover:text-[#202522]'
              }`}
            >
              {type.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Threat Feed List */}
      <div className="space-y-4">
        {filteredReports.length === 0 ? (
          <div className="bg-white border border-[#E2E5E1] rounded-2xl p-12 text-center text-xs text-[#747C78]">
            No threat intelligence records matched your search query.
          </div>
        ) : (
          filteredReports.map((report) => (
            <div
              key={report.id}
              className="bg-white border border-[#E2E5E1] rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] flex flex-col md:flex-row md:items-center justify-between gap-5 hover:border-[#D5DAD3] transition-all"
            >
              <div className="space-y-2 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider ${
                    report.status === 'VERIFIED' ? 'bg-[#B42318]/10 text-[#B42318]' :
                    report.status === 'DISPUTED' ? 'bg-neutral-200 text-neutral-800' :
                    'bg-amber-100 text-amber-900'
                  }`}>
                    {report.status}
                  </span>

                  <span className="text-[11px] font-mono font-semibold px-2 py-0.5 bg-neutral-100 rounded text-[#202522]">
                    {report.threatType}
                  </span>

                  {report.targetedBrand && (
                    <span className="text-[11px] font-semibold text-[#D97706] bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                      Target: {report.targetedBrand}
                    </span>
                  )}

                  <span className="text-xs text-[#747C78] font-mono">
                    Report ID: {report.id} · {new Date(report.submittedAt).toLocaleDateString()}
                  </span>
                </div>

                <div className="text-sm font-bold font-mono text-[#202522] break-all">
                  {report.url}
                </div>

                <p className="text-xs text-[#555C57]">
                  <strong>Evidence Notes:</strong> {report.evidenceNotes}
                </p>

                <div className="text-[11px] text-[#747C78] font-mono">
                  Reporter: <span className="text-[#202522]">{report.submittedBy}</span> · Peer Verifications: <strong className="text-emerald-700">{report.verificationsCount}</strong> · Disputes: <strong className="text-red-700">{report.disputesCount}</strong>
                </div>
              </div>

              {/* Action column */}
              <div className="flex items-center gap-4 shrink-0 border-t md:border-t-0 md:border-l border-neutral-100 pt-3 md:pt-0 md:pl-5">
                <div className="text-center">
                  <div className="text-2xl font-bold font-mono tabular-nums text-[#202522]">
                    {report.reputationScore}%
                  </div>
                  <div className="text-[10px] text-[#747C78] uppercase font-semibold">Reputation</div>
                </div>

                <div className="flex flex-col gap-2">
                  <button
                    onClick={() => onScanUrl(report.url)}
                    className="px-3.5 py-1.5 bg-[#F7F7F4] hover:bg-[#EAECE8] border border-[#E2E5E1] text-[#202522] rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <span>Run Scanner</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onVerifyReport(report.id, true)}
                      title="Verify and confirm this threat"
                      className="px-2.5 py-1 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors"
                    >
                      <ThumbsUp className="w-3 h-3" />
                      <span>Verify</span>
                    </button>
                    <button
                      onClick={() => onVerifyReport(report.id, false)}
                      title="Dispute inaccurate report"
                      className="px-2.5 py-1 bg-red-50 hover:bg-red-100 text-red-800 border border-red-200 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors"
                    >
                      <ThumbsDown className="w-3 h-3" />
                      <span>Dispute</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
