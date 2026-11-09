/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { TopNav, TopNavTab } from './components/TopNav';
import { InvestigationHeader } from './components/InvestigationHeader';
import { MainInvestigationView } from './components/MainInvestigationView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { CertificatesView } from './components/CertificatesView';
import { HistoryView } from './components/HistoryView';
import { SubmitReportModal } from './components/SubmitReportModal';
import { LiveScannerView } from './components/LiveScannerView';
import { ScanResult, ThreatReport, DashboardOverview } from './types';

export default function App() {
  const [topTab, setTopTab] = useState<TopNavTab>('investigate');
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [threatReports, setThreatReports] = useState<ThreatReport[]>([]);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [submittedUrl, setSubmittedUrl] = useState('');
  const [errorAlert, setErrorAlert] = useState<string | null>(null);
  const activeScanRequest = useRef(0);

  // Submit Modal
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [modalInitialUrl, setModalInitialUrl] = useState('');
  const [modalInitialDomain, setModalInitialDomain] = useState('');

  // Fetch initial cases & intelligence
  const loadData = async () => {
    try {
      const [scRes, tiRes, ovRes] = await Promise.all([
        fetch('/api/v1/scans'),
        fetch('/api/v1/threat-intelligence'),
        fetch('/api/v1/dashboard/overview'),
      ]);

      if (scRes.ok) {
        const scData = await scRes.json();
        setScans(scData.scans || []);
      }

      if (tiRes.ok) {
        const tiData = await tiRes.json();
        setThreatReports(tiData.reports || []);
      }

      if (ovRes.ok) {
        const ovData = await ovRes.json();
        setOverview(ovData);
      }
    } catch (err) {
      console.error('Failed to load Sentinel initial data:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Run dynamic scan on any submitted URL
  const handleExecuteScan = async (url: string) => {
    const requestId = ++activeScanRequest.current;
    setSubmittedUrl(url);
    setCurrentScan(null);
    setTopTab('investigate');
    setIsScanning(true);
    setErrorAlert(null);
    try {
      const response = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.details || data.error || 'Scan failed.');
      }

      if (requestId === activeScanRequest.current) {
        setCurrentScan(data);
        void loadData();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (requestId === activeScanRequest.current) setErrorAlert(msg);
    } finally {
      if (requestId === activeScanRequest.current) setIsScanning(false);
    }
  };

  // Export JSON Report
  const handleExportReport = () => {
    if (!currentScan) return;
    const blob = new Blob([JSON.stringify(currentScan, null, 2)], { type: 'application/json' });
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = `sentinel-case-${currentScan.id}-${currentScan.domain}.json`;
    a.click();
    URL.revokeObjectURL(href);
  };

  // Submit Community Report
  const handleSubmitReport = async (reportData: {
    url: string;
    domain: string;
    threatType: 'PHISHING' | 'MALWARE' | 'BRAND_IMPERSONATION' | 'CREDENTIAL_HARVESTING' | 'PAYMENT_FRAUD';
    targetedBrand?: string;
    evidenceNotes: string;
    submittedBy: string;
  }) => {
    try {
      const res = await fetch('/api/v1/threat-reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportData),
      });
      if (res.ok) {
        const newReport = await res.json();
        setThreatReports((prev) => [newReport, ...prev]);
        loadData();
      } else {
        const error = await res.json();
        setErrorAlert(error.error || 'Community report could not be submitted.');
      }
    } catch (err) {
      console.error('Failed to submit report:', err);
    }
  };

  // Verify Threat Report
  const handleVerifyReport = async (reportId: string, isAffirmative: boolean) => {
    try {
      const res = await fetch(`/api/v1/threat-reports/${reportId}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isAffirmative }),
      });
      if (res.ok) {
        const updated = await res.json();
        setThreatReports((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      } else {
        const error = await res.json();
        setErrorAlert(error.error || 'Community report could not be verified.');
      }
    } catch (err) {
      console.error('Failed to verify report:', err);
    }
  };

  const handleOpenReportModal = (url = '', domain = '') => {
    setModalInitialUrl(url || currentScan?.targetUrl || '');
    setModalInitialDomain(domain || currentScan?.domain || '');
    setIsReportModalOpen(true);
  };

  return (
    <div className="min-h-screen bg-[#F4F5F1] text-[#14231C] flex flex-col font-sans selection:bg-[#2E7D52]/20 selection:text-[#14231C]">
      {/* 1. TOP NAVIGATION BAR */}
      <TopNav
        activeTab={topTab}
        onSelectTab={setTopTab}
        openThreatsCount={overview?.openFindingsCount || 0}
      />

      {/* Global Error Notice if any */}
      {errorAlert && (
        <div className="mx-8 mt-4 p-3.5 bg-red-50 border border-red-200 rounded-xl text-xs text-red-800 flex items-center justify-between shadow-xs">
          <div className="flex items-center gap-2">
            <strong className="font-mono">[INVESTIGATION ERROR]</strong>
            <span>{errorAlert}</span>
          </div>
          <button
            onClick={() => setErrorAlert(null)}
            className="text-red-600 hover:text-red-900 font-bold ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 2. TAB BODY */}
      <div className="flex-1">
        {/* TAB 1: INVESTIGATE (THE NEW SIGNATURE VIEW) */}
        {topTab === 'investigate' && !currentScan && (
          <LiveScannerView
            isLoading={isScanning}
            submittedUrl={submittedUrl}
            onExecuteScan={handleExecuteScan}
          />
        )}

        {topTab === 'investigate' && currentScan && (
          <div>
            <InvestigationHeader
              currentScan={currentScan}
              onExportReport={handleExportReport}
              onScanUrl={handleExecuteScan}
              isLoading={isScanning}
            />

            <MainInvestigationView
              scan={currentScan}
              onOpenReportModal={() => handleOpenReportModal()}
            />
          </div>
        )}

        {/* TAB 2 & 5: INTELLIGENCE & COMMUNITY */}
        {(topTab === 'intelligence' || topTab === 'community') && (
          <ThreatIntelView
            reports={threatReports}
            onOpenReportModal={() => handleOpenReportModal()}
            onVerifyReport={handleVerifyReport}
            onScanUrl={(url) => {
              handleExecuteScan(url);
              setTopTab('investigate');
            }}
          />
        )}

        {/* TAB 3: CERTIFICATES */}
        {topTab === 'certificates' && <CertificatesView />}

        {/* TAB 4: REPORTS */}
        {topTab === 'reports' && (
          <HistoryView
            scans={scans}
            onSelectScan={(selected) => {
              setCurrentScan(selected);
              setTopTab('investigate');
            }}
            onRescan={(url) => {
              handleExecuteScan(url);
              setTopTab('investigate');
            }}
          />
        )}
      </div>

      {/* Submit Report Modal */}
      <SubmitReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        onSubmit={handleSubmitReport}
        initialUrl={modalInitialUrl}
        initialDomain={modalInitialDomain}
      />
    </div>
  );
}
