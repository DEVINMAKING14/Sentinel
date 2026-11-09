import React, { useState, useEffect } from 'react';
import { 
  Download, 
  Bookmark, 
  ExternalLink, 
  Search, 
  Check, 
  Globe,
  Loader2,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { ScanResult } from '../types';

interface InvestigationHeaderProps {
  currentScan: ScanResult;
  onExportReport: () => void;
  onScanUrl: (url: string) => Promise<void>;
  isLoading: boolean;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  currentScan,
  onExportReport,
  onScanUrl,
  isLoading,
}) => {
  const [customUrl, setCustomUrl] = useState('');
  const [isWatchlisted, setIsWatchlisted] = useState(false);
  const [activeScanStage, setActiveScanStage] = useState(0);

  const pipelineStages = [
    'Resolving DNS and applying SSRF checks',
    'Retrieving the submitted website response',
    'Inspecting TLS and redirect evidence',
    'Analyzing URL and retrieved page content',
    'Checking submitted community reports',
    'Calculating risk from available evidence',
  ];

  // Sync Watchlist from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('sentinel_watchlist');
      if (stored) {
        const list: string[] = JSON.parse(stored);
        setIsWatchlisted(list.includes(currentScan.id) || list.includes(currentScan.domain));
      } else {
        setIsWatchlisted(false);
      }
    } catch {
      setIsWatchlisted(false);
    }
  }, [currentScan.id, currentScan.domain]);

  const toggleWatchlist = () => {
    try {
      const stored = localStorage.getItem('sentinel_watchlist');
      let list: string[] = stored ? JSON.parse(stored) : [];
      if (isWatchlisted) {
        list = list.filter((id) => id !== currentScan.id && id !== currentScan.domain);
        setIsWatchlisted(false);
      } else {
        list.push(currentScan.id);
        list.push(currentScan.domain);
        setIsWatchlisted(true);
      }
      localStorage.setItem('sentinel_watchlist', JSON.stringify(list));
    } catch (e) {
      console.error('Failed to update watchlist in localStorage:', e);
    }
  };

  // Animate through pipeline stages when scanning
  useEffect(() => {
    let interval: any;
    if (isLoading) {
      setActiveScanStage(0);
      interval = setInterval(() => {
        setActiveScanStage((prev) => (prev < pipelineStages.length - 1 ? prev + 1 : prev));
      }, 700);
    }
    return () => clearInterval(interval);
  }, [isLoading]);

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUrl.trim() || isLoading) return;
    onScanUrl(customUrl);
    setCustomUrl('');
  };

  return (
    <div className="border-b border-[#E2E5E1] bg-white/70 relative">
      {/* 1. TOP URL SCAN BAR */}
      <div className="px-8 pt-4 pb-3 bg-[#F4F5F1]/80 border-b border-[#E2E5E1]">
        <div className="flex flex-col lg:flex-row lg:items-center gap-3 justify-between">
          {/* Search Form */}
          <form onSubmit={handleCustomSubmit} className="flex-1 max-w-3xl flex gap-2">
            <div className="relative flex-1">
              <Globe className="w-4 h-4 absolute left-3.5 top-3 text-[#747C78]" />
              <input
                type="text"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="Scan any website address (e.g., https://secure-bank.org, www.example.com, or apex domain)..."
                className="w-full pl-10 pr-4 py-2.5 bg-white border border-[#D5DAD3] rounded-xl text-xs font-mono text-[#14231C] placeholder:text-[#8E9690] focus:outline-hidden focus:ring-2 focus:ring-[#14231C]/20 transition-all shadow-2xs"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !customUrl.trim()}
              className="px-5 py-2.5 bg-[#14231C] hover:bg-[#203329] disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition-all shrink-0 shadow-xs"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Probing Target...</span>
                </>
              ) : (
                <>
                  <span>Investigate Target</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

        </div>

        {/* Live Async Scanning Pipeline Progress Bar */}
        {isLoading && (
          <div className="mt-3 p-3 bg-white border border-[#B5D8C3] rounded-xl shadow-xs animate-in fade-in slide-in-from-top-1 duration-200">
            <div className="flex items-center justify-between text-xs mb-2">
              <div className="flex items-center gap-2 font-semibold text-[#14231C]">
                <Loader2 className="w-4 h-4 animate-spin text-[#2E7D52]" />
                <span>Multi-Vector Prober Running: <strong className="font-mono text-[#2E7D52]">{pipelineStages[activeScanStage]}</strong></span>
              </div>
              <span className="text-[11px] font-mono text-[#747C78]">Stage {activeScanStage + 1} of 6</span>
            </div>
            {/* Stage Step Indicators */}
            <div className="grid grid-cols-6 gap-1.5">
              {pipelineStages.map((stage, idx) => (
                <div
                  key={idx}
                  className={`h-1.5 rounded-full transition-all duration-300 ${
                    idx < activeScanStage
                      ? 'bg-[#2E7D52]'
                      : idx === activeScanStage
                      ? 'bg-[#2E7D52] animate-pulse'
                      : 'bg-[#E2E5E1]'
                  }`}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 2. CASE HEADER & METADATA (EXACT MATCH OF IMAGE_C2443C7D.PNG) */}
      <div className="px-8 py-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Left: Breadcrumbs & Title */}
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#747C78] mb-1">
            <span>Investigate</span>
            <span>/</span>
            <span className="text-[#202522] font-semibold">Case #{currentScan.id}</span>
          </div>

          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold font-mono tracking-tight text-[#14231C] flex items-center gap-2">
              <span>Investigation: {currentScan.domain}</span>
              <a
                href={currentScan.targetUrl}
                target="_blank"
                rel="noreferrer noopener"
                className="text-[#747C78] hover:text-[#14231C] transition-colors"
                title="Open target in isolated browser window"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </h1>
          </div>

          <div className="flex items-center gap-2 text-xs text-[#747C78] mt-1 font-sans">
            <span>Case #{currentScan.id}</span>
            <span>·</span>
            <span>Scanned {new Date(currentScan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            <span>·</span>
            <span className="font-medium text-[#426B57]">Automated Analysis</span>
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={onExportReport}
            className="flex items-center gap-2 px-4 py-2 bg-white hover:bg-neutral-50 text-[#14231C] border border-[#D5DAD3] rounded-xl text-xs font-semibold shadow-xs transition-all active:scale-98"
          >
            <Download className="w-4 h-4 text-[#747C78]" />
            <span>Export Report</span>
          </button>

          <button
            onClick={toggleWatchlist}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold shadow-xs transition-all active:scale-98 ${
              isWatchlisted
                ? 'bg-[#2E7D52] text-white'
                : 'bg-[#14231C] hover:bg-[#203329] text-white'
            }`}
          >
            {isWatchlisted ? (
              <>
                <Check className="w-4 h-4 text-emerald-300" />
                <span>On Watchlist</span>
              </>
            ) : (
              <>
                <Bookmark className="w-4 h-4" />
                <span>Add to Watchlist</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
