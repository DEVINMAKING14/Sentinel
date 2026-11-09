import React, { useState } from 'react';
import { 
  GitFork, 
  Maximize2, 
  Minimize2, 
  Plus, 
  Minus, 
  ShieldCheck, 
  Globe, 
  Server, 
  Users, 
  FileText, 
  Landmark, 
  ArrowLeftRight, 
  Monitor,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';
import { ScanResult } from '../types';

interface ThreatRelationshipMapProps {
  scan: ScanResult;
  onSelectNodeDetail?: (type: string) => void;
}

export const ThreatRelationshipMap: React.FC<ThreatRelationshipMapProps> = ({
  scan,
  onSelectNodeDetail,
}) => {
  const [zoomLevel, setZoomLevel] = useState(1);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeNode, setActiveNode] = useState<string | null>(null);

  const handleZoom = (delta: number) => {
    setZoomLevel((prev) => Math.min(1.4, Math.max(0.7, prev + delta)));
  };

  const domain = scan.domain;
  const ipAddress = scan.resolvedIp || 'Not Resolved';
  
  const urlIndicatorCount = scan.phishingAnalysis.indicators.length;

  // Dynamic Node 2: Redirects
  const redirectCount = scan.redirectChain.length;
  const hasMultipleHops = redirectCount > 1;

  // Dynamic Node 3: TLS Certificate
  const tlsAvailable = scan.modules?.tls.status === 'completed' || Boolean(scan.tlsCertificate.validFrom);
  const tlsIssuer = scan.tlsCertificate.issuer.commonName || scan.tlsCertificate.issuer.organization || 'Unavailable';
  const isTlsValid = tlsAvailable && scan.tlsCertificate.valid && !scan.tlsCertificate.isExpired && !scan.tlsCertificate.isSelfSigned;

  // Dynamic Node 5: Hosting / ASN
  const hostingName = scan.hostingProvider || 'Unknown Provider';

  // Dynamic Node 6: Threat Reports
  const reportsCount = scan.threatIntelMatches.length > 0 
    ? (scan.threatIntelMatches[0].reportCount || scan.threatIntelMatches.length) 
    : 0;

  // Dynamic Node 7: Form Status
  const contentAvailable = scan.modules?.http.status !== 'unavailable';
  const hasSensitiveForm = Boolean(scan.phishingAnalysis.hasCredentialInputs);

  // Central Node Risk Level Styling
  const isHighRisk = scan.riskScore >= 70;
  const isMediumRisk = scan.riskScore >= 40 && scan.riskScore < 70;
  const isSafe = scan.riskScore < 40;

  return (
    <div className={`bg-white border border-[#E2E5E1] rounded-2xl shadow-[0_1px_3px_rgba(0,0,0,0.04)] overflow-hidden transition-all ${
      isFullscreen ? 'fixed inset-4 z-50 flex flex-col' : 'relative'
    }`}>
      {/* Card Header */}
      <div className="px-6 py-4 border-b border-[#E2E5E1] flex items-center justify-between bg-white z-10">
        <div className="flex items-center gap-2.5">
          <GitFork className="w-4 h-4 text-[#747C78]" />
          <div>
            <h2 className="text-sm font-bold text-[#14231C]">Threat Relationship Map</h2>
            <p className="text-[11px] text-[#747C78]">Entities and evidence linked to this domain</p>
          </div>
        </div>

        {/* Canvas Toolbar Controls */}
        <div className="flex items-center gap-1.5 bg-[#F4F5F1] p-1 rounded-xl border border-[#D5DAD3]">
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen Map'}
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white text-[#555C57] hover:text-[#14231C] transition-colors"
          >
            {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
          <div className="w-[1px] h-3.5 bg-[#D5DAD3]" />
          <button
            onClick={() => handleZoom(0.1)}
            title="Zoom In"
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white text-[#555C57] hover:text-[#14231C] transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => handleZoom(-0.1)}
            title="Zoom Out"
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white text-[#555C57] hover:text-[#14231C] transition-colors"
          >
            <Minus className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Interactive Graph Canvas Area */}
      <div className={`relative w-full bg-[#FAFBF9] bg-dot-grid overflow-hidden select-none ${
        isFullscreen ? 'flex-1' : 'h-[370px]'
      }`}>
        {/* Scalable Container */}
        <div
          className="absolute inset-0 flex items-center justify-center transition-transform duration-150"
          style={{ transform: `scale(${zoomLevel})` }}
        >
          <div className="relative w-[780px] h-[340px]">
            {/* SVG Bezier Connector Curves */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none" xmlns="http://www.w3.org/2000/svg">
              {/* Curve 1: Center to Brand Impersonation (Left) */}
              <path
                d="M 390 170 C 320 170, 300 175, 220 175"
                fill="none"
                stroke={urlIndicatorCount > 0 ? '#E5A6A0' : '#B5D8C3'}
                strokeWidth="1.5"
                strokeDasharray={urlIndicatorCount > 0 ? '4 2' : undefined}
              />

              {/* Curve 2: Center to Redirects (Top Left) */}
              <path
                d="M 390 170 C 360 110, 350 90, 310 80"
                fill="none"
                stroke={hasMultipleHops ? '#E7C79A' : '#B5D8C3'}
                strokeWidth="1.5"
              />

              {/* Curve 3: Center to TLS Certificate (Top Middle) */}
              <path
                d="M 390 170 C 390 120, 390 90, 390 60"
                fill="none"
                stroke={isTlsValid ? '#B5D8C3' : '#E5A6A0'}
                strokeWidth="1.5"
              />

              {/* Curve 4: Center to IP Address (Top Right) */}
              <path
                d="M 390 170 C 440 120, 470 100, 520 85"
                fill="none"
                stroke="#CFD5CF"
                strokeWidth="1.5"
              />

              {/* Curve 5: Center to Hosting / ASN (Right) */}
              <path
                d="M 390 170 C 460 170, 500 175, 560 175"
                fill="none"
                stroke="#B5D8C3"
                strokeWidth="1.5"
              />

              {/* Curve 6: Center to Threat Reports (Bottom Right) */}
              <path
                d="M 390 170 C 440 220, 480 230, 520 250"
                fill="none"
                stroke={reportsCount > 0 ? '#E7C79A' : '#B5D8C3'}
                strokeWidth="1.5"
              />

              {/* Curve 7: Center to Suspicious Form (Bottom Left) */}
              <path
                d="M 390 170 C 340 220, 310 230, 270 250"
                fill="none"
                stroke={hasSensitiveForm ? '#E5A6A0' : '#B5D8C3'}
                strokeWidth="1.5"
                strokeDasharray={hasSensitiveForm ? '4 2' : undefined}
              />
            </svg>

            {/* NODE 0: CENTRAL TARGET */}
            <div
              onClick={() => setActiveNode('target')}
              className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-20 cursor-pointer"
            >
              <div className={`px-5 py-3.5 border-2 rounded-2xl shadow-md flex flex-col items-center justify-center min-w-[210px] hover:shadow-lg transition-all group ${
                isHighRisk 
                  ? 'bg-[#FFF5F4] border-[#E06A5E]' 
                  : isMediumRisk 
                  ? 'bg-[#FFFDF9] border-[#E07A2A]' 
                  : 'bg-[#F1F8F4] border-[#2E7D52]'
              }`}>
                <div className={`w-8 h-8 rounded-xl flex items-center justify-center mb-1.5 shadow-xs ${
                  isHighRisk 
                    ? 'bg-[#FDE8E6] text-[#C93B2B]' 
                    : isMediumRisk 
                    ? 'bg-[#FEF4E8] text-[#E07A2A]' 
                    : 'bg-[#E2F2E9] text-[#2E7D52]'
                }`}>
                  <Monitor className="w-4 h-4" />
                </div>
                <div className="text-xs font-bold font-mono text-[#14231C] tracking-tight group-hover:text-[#2E7D52] transition-colors truncate max-w-[190px]">
                  {domain}
                </div>
                <div className={`text-[11px] font-semibold mt-0.5 ${
                  isHighRisk ? 'text-[#C93B2B]' : isMediumRisk ? 'text-[#E07A2A]' : 'text-[#2E7D52]'
                }`}>
                  {isHighRisk ? 'High observed risk' : isMediumRisk ? 'Elevated observed risk' : 'Low observed indicators (not a safety verdict)'}
                </div>
              </div>
            </div>

            {/* NODE 1: BRAND IMPERSONATION / AUTHENTICITY (Left) */}
            <div
              onClick={() => setActiveNode('brand')}
              style={{ left: '20px', top: '145px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className={`relative px-3.5 py-2.5 border rounded-xl shadow-xs flex items-center gap-3 transition-all ${
                urlIndicatorCount > 0 
                  ? 'bg-[#FFFAF9] border-[#E5A6A0] hover:border-[#C93B2B]' 
                  : 'bg-[#F6FAF7] border-[#B5D8C3] hover:border-[#2E7D52]'
              }`}>
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                  urlIndicatorCount > 0 ? 'bg-[#C93B2B]' : 'bg-[#2E7D52]'
                }`} />
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                  urlIndicatorCount > 0 ? 'bg-[#FDE8E6] text-[#C93B2B]' : 'bg-[#E2F2E9] text-[#2E7D52]'
                }`}>
                  <Landmark className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">
                    {'URL Indicators'}
                  </div>
                  <div className="text-[10px] text-[#747C78]">
                    {urlIndicatorCount > 0
                      ? `${urlIndicatorCount} URL indicator${urlIndicatorCount === 1 ? '' : 's'} observed`
                      : 'No URL heuristic matches'}
                  </div>
                </div>
              </div>
            </div>

            {/* NODE 2: REDIRECTS (Top Left) */}
            <div
              onClick={() => setActiveNode('redirects')}
              style={{ left: '160px', top: '55px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className={`relative px-3.5 py-2 border rounded-xl shadow-xs flex items-center gap-3 transition-all ${
                hasMultipleHops 
                  ? 'bg-[#FFFDF9] border-[#E7C79A] hover:border-[#D97706]' 
                  : 'bg-[#F6FAF7] border-[#B5D8C3] hover:border-[#2E7D52]'
              }`}>
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                  hasMultipleHops ? 'bg-[#E07A2A]' : 'bg-[#2E7D52]'
                }`} />
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                  hasMultipleHops ? 'bg-[#FEF4E8] text-[#E07A2A]' : 'bg-[#E2F2E9] text-[#2E7D52]'
                }`}>
                  <ArrowLeftRight className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">Redirects</div>
                  <div className="text-[10px] text-[#747C78]">
                    {hasMultipleHops ? `${redirectCount} hops observed` : scan.modules?.http.status === 'unavailable' ? 'Unavailable' : 'No redirects observed'}
                  </div>
                </div>
              </div>
            </div>

            {/* NODE 3: TLS CERTIFICATE (Top Middle) */}
            <div
              onClick={() => setActiveNode('tls')}
              style={{ left: '315px', top: '25px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className={`relative px-4 py-2 border rounded-xl shadow-xs flex items-center gap-3 transition-all ${
                isTlsValid 
                  ? 'bg-[#F1F8F4] border-[#B5D8C3] hover:border-[#2E7D52]' 
                  : 'bg-[#FFFAF9] border-[#E5A6A0] hover:border-[#C93B2B]'
              }`}>
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                  isTlsValid ? 'bg-[#2E7D52]' : 'bg-[#C93B2B]'
                }`} />
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                  isTlsValid ? 'bg-[#E2F2E9] text-[#2E7D52]' : 'bg-[#FDE8E6] text-[#C93B2B]'
                }`}>
                  <ShieldCheck className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">TLS Certificate</div>
                  <div className={`text-[10px] font-medium truncate max-w-[150px] ${
                    isTlsValid ? 'text-[#2E7D52]' : 'text-[#C93B2B]'
                  }`}>
                    {tlsAvailable ? `${tlsIssuer} (${isTlsValid ? 'Valid' : 'Untrusted'})` : 'Certificate unavailable'}
                  </div>
                </div>
              </div>
            </div>

            {/* NODE 4: IP ADDRESS (Top Right) */}
            <div
              onClick={() => setActiveNode('ip')}
              style={{ left: '490px', top: '60px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className="relative px-3.5 py-2 bg-white border border-[#D5DAD3] rounded-xl shadow-xs flex items-center gap-3 hover:border-[#14231C] hover:shadow-sm transition-all">
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#E07A2A] ring-2 ring-white" />
                <div className="w-7 h-7 rounded-lg bg-[#F4F5F1] flex items-center justify-center text-[#2E7D52]">
                  <Globe className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">IP Address</div>
                  <div className="text-[10px] font-mono text-[#555C57]">{ipAddress}</div>
                </div>
              </div>
            </div>

            {/* NODE 5: HOSTING / ASN (Right) */}
            <div
              onClick={() => setActiveNode('hosting')}
              style={{ left: '550px', top: '145px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className="relative px-3.5 py-2.5 bg-white border border-[#B5D8C3] rounded-xl shadow-xs flex items-center gap-3 hover:border-[#2E7D52] hover:shadow-sm transition-all bg-[#F6FAF7]">
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#2E7D52] ring-2 ring-white" />
                <div className="w-7 h-7 rounded-lg bg-[#E2F2E9] flex items-center justify-center text-[#2E7D52]">
                  <Server className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">Hosting / ASN</div>
                  <div className="text-[10px] text-[#555C57] truncate max-w-[140px]">{hostingName}</div>
                </div>
              </div>
            </div>

            {/* NODE 6: THREAT REPORTS (Bottom Right) */}
            <div
              onClick={() => setActiveNode('threats')}
              style={{ left: '490px', top: '235px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className={`relative px-3.5 py-2.5 border rounded-xl shadow-xs flex items-center gap-3 transition-all ${
                reportsCount > 0 
                  ? 'bg-[#FFFDF9] border-[#E7C79A] hover:border-[#D97706]' 
                  : 'bg-[#F6FAF7] border-[#B5D8C3] hover:border-[#2E7D52]'
              }`}>
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                  reportsCount > 0 ? 'bg-[#E07A2A]' : 'bg-[#2E7D52]'
                }`} />
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                  reportsCount > 0 ? 'bg-[#FEF4E8] text-[#E07A2A]' : 'bg-[#E2F2E9] text-[#2E7D52]'
                }`}>
                  <Users className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">Threat Reports</div>
                  <div className="text-[10px] text-[#747C78]">
                    {reportsCount > 0 ? `${reportsCount} community reports` : 'No matching reports'}
                  </div>
                </div>
              </div>
            </div>

            {/* NODE 7: SUSPICIOUS FORM / FORM SURFACE (Bottom Left) */}
            <div
              onClick={() => setActiveNode('form')}
              style={{ left: '160px', top: '235px' }}
              className="absolute z-10 cursor-pointer"
            >
              <div className={`relative px-3.5 py-2.5 border rounded-xl shadow-xs flex items-center gap-3 transition-all ${
                hasSensitiveForm 
                  ? 'bg-[#FFFAF9] border-[#E5A6A0] hover:border-[#C93B2B]' 
                  : 'bg-[#F6FAF7] border-[#B5D8C3] hover:border-[#2E7D52]'
              }`}>
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full ring-2 ring-white ${
                  hasSensitiveForm ? 'bg-[#C93B2B]' : 'bg-[#2E7D52]'
                }`} />
                <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                  hasSensitiveForm ? 'bg-[#FDE8E6] text-[#C93B2B]' : 'bg-[#E2F2E9] text-[#2E7D52]'
                }`}>
                  <FileText className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <div className="text-xs font-bold text-[#14231C]">
                    {hasSensitiveForm ? 'Sensitive Input' : 'Page Content'}
                  </div>
                  <div className={`text-[10px] font-semibold ${
                    hasSensitiveForm ? 'text-[#C93B2B]' : 'text-[#2E7D52]'
                  }`}>
                    {hasSensitiveForm ? 'Input observed' : contentAvailable ? 'No sensitive input observed' : 'Content unavailable'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Node Detail Peek Drawer if active */}
        {activeNode && (
          <div className="absolute bottom-3 left-6 right-6 p-3 bg-white/95 border border-[#D5DAD3] rounded-xl shadow-md text-xs flex items-center justify-between animate-in fade-in slide-in-from-bottom-2 duration-150 backdrop-blur-xs">
            <div className="flex items-center gap-2 text-[#14231C]">
              <Info className="w-4 h-4 text-[#426B57] shrink-0" />
              <span>
                {activeNode === 'target' && `Primary target host: ${domain}. Overall risk evaluation: ${scan.riskScore}/100 (${scan.riskCategory}).`}
                {activeNode === 'brand' && (urlIndicatorCount > 0
                  ? `${urlIndicatorCount} URL-based heuristic indicator(s) were observed.`
                  : 'No URL-based heuristic indicators matched; that does not verify the site identity.')}
                {activeNode === 'redirects' && (hasMultipleHops 
                  ? `Redirection chain: ${redirectCount} hops detected between initial URI and final destination.` 
                  : scan.modules?.http.status === 'unavailable'
                    ? `Redirect analysis unavailable: ${scan.modules.http.message || 'No HTTP response was received.'}`
                    : `No intermediate HTTP redirects were observed.`)}
                {activeNode === 'tls' && (tlsAvailable
                  ? `${isTlsValid ? 'Valid' : 'Untrusted'} TLS certificate issued by ${tlsIssuer}. TLS does not verify site legitimacy.`
                  : `TLS certificate unavailable: ${scan.modules?.tls.message || 'No certificate was retrieved.'}`)}
                {activeNode === 'ip' && `Resolved IP: ${ipAddress} routing via ${hostingName} network.`}
                {activeNode === 'hosting' && `Hosting Provider: ${hostingName}. AS Number: ${scan.asn || 'Unknown'}.`}
                {activeNode === 'threats' && (reportsCount > 0 
                  ? `${reportsCount} correlated community threat reports matched in Sentinel intelligence database.` 
                  : `No community threat report matched; this is not a clean verdict.`)}
                {activeNode === 'form' && (hasSensitiveForm
                  ? 'Sensitive input fields were observed in the retrieved page.'
                  : contentAvailable
                    ? 'No password or payment input fields were observed in the retrieved page.'
                    : 'Page content was unavailable, so form analysis could not be completed.')}
              </span>
            </div>
            <div className="flex items-center gap-3 ml-4 shrink-0">
              {onSelectNodeDetail && (
                <button
                  onClick={() => {
                    if (activeNode === 'tls') onSelectNodeDetail('certificate');
                    else if (activeNode === 'threats') onSelectNodeDetail('threat-intel');
                    else onSelectNodeDetail('findings');
                  }}
                  className="px-2 py-1 bg-[#14231C] text-white rounded text-[11px] font-semibold"
                >
                  View Details
                </button>
              )}
              <button
                onClick={() => setActiveNode(null)}
                className="text-[#747C78] hover:text-[#14231C] font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
