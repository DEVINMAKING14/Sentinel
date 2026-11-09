import React, { useEffect, useState } from 'react';
import { Globe, Search, Shield } from 'lucide-react';

interface LiveScannerViewProps {
  isLoading: boolean;
  submittedUrl: string;
  onExecuteScan: (url: string) => Promise<void>;
}

export const LiveScannerView: React.FC<LiveScannerViewProps> = ({
  isLoading,
  submittedUrl,
  onExecuteScan,
}) => {
  const [urlInput, setUrlInput] = useState('');
  useEffect(() => {
    if (submittedUrl) setUrlInput(submittedUrl);
  }, [submittedUrl]);

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!urlInput.trim() || isLoading) return;
    onExecuteScan(urlInput);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-8">
      <section className="rounded-2xl border border-[#E2E5E1] bg-white p-6 shadow-sm">
        <h1 className="text-xl font-bold text-[#202522]">SENTINEL Web Observatory</h1>
        <p className="mt-2 text-sm text-[#747C78]">
          Investigate any public HTTP or HTTPS website. Each submission triggers a fresh inspection of the URL you provide.
        </p>
        <form onSubmit={handleSubmit} className="mt-5 flex flex-col gap-3 sm:flex-row">
          <label className="relative flex-1">
            <span className="sr-only">Website URL or domain</span>
            <Globe className="absolute left-3.5 top-3.5 h-4 w-4 text-[#747C78]" />
            <input
              type="text"
              value={urlInput}
              onChange={event => setUrlInput(event.target.value)}
              placeholder="Enter any website URL or domain"
              className="w-full rounded-xl border border-[#E2E5E1] bg-[#F7F7F4] py-3 pl-10 pr-4 text-sm font-mono text-[#202522] focus:border-[#426B57] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
              disabled={isLoading}
            />
          </label>
          <button
            type="submit"
            disabled={isLoading || !urlInput.trim()}
            className="flex shrink-0 items-center justify-center gap-2 rounded-xl bg-[#202522] px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-[#323935] disabled:opacity-50"
          >
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                Investigating
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                Investigate
              </>
            )}
          </button>
        </form>
      </section>

      {isLoading && (
        <section className="rounded-2xl border border-[#E2E5E1] bg-white p-8 text-center shadow-sm" aria-live="polite">
          <Shield className="mx-auto mb-3 h-7 w-7 animate-pulse text-[#426B57]" />
          <h2 className="text-base font-bold text-[#202522]">
            Investigation: {(() => {
              try {
                const value = submittedUrl.match(/^https?:\/\//i) ? submittedUrl : `https://${submittedUrl}`;
                return new URL(value).hostname;
              } catch {
                return submittedUrl;
              }
            })()}
          </h2>
          <p className="mx-auto mt-2 max-w-2xl break-all font-mono text-xs text-[#555C57]">{submittedUrl}</p>
          <p className="mt-3 text-xs text-[#747C78]">
            Results from unavailable modules will be marked unavailable; no substitute website or prior scan is used.
          </p>
        </section>
      )}
    </div>
  );
};
