import React, { useState } from 'react';
import { ScanResult, Finding } from '../types';
import { InvestigationSubTabs, SubTabType } from './InvestigationSubTabs';
import { InvestigationFlowSidebar } from './InvestigationFlowSidebar';
import { ThreatRelationshipMap } from './ThreatRelationshipMap';
import { InvestigationTimeline } from './InvestigationTimeline';
import { KeyEvidenceCard } from './KeyEvidenceCard';
import { RiskAssessmentPanel } from './RiskAssessmentPanel';
import { 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  ShieldCheck, 
  Layers, 
  Copy, 
  Check 
} from 'lucide-react';

interface MainInvestigationViewProps {
  scan: ScanResult;
  onOpenReportModal: () => void;
}

export const MainInvestigationView: React.FC<MainInvestigationViewProps> = ({
  scan,
  onOpenReportModal,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<SubTabType>('lab');
  const [copiedJson, setCopiedJson] = useState(false);

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="p-8 max-w-[1520px] mx-auto space-y-6">
      <section className="bg-white border border-[#E2E5E1] rounded-2xl p-5 shadow-sm" aria-label="Investigation evidence status">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#E2E5E1] pb-3">
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-[#14231C]">Investigation evidence</h2>
            <p className="mt-1 break-all text-xs font-mono text-[#555C57]">
              Submitted: {scan.submittedUrl || scan.targetUrl}
            </p>
            <p className="mt-1 text-[11px] text-[#747C78]">
              Canonical host: <span className="font-mono">{scan.domain}</span> · Scan ID: <span className="font-mono">{scan.id}</span>
            </p>
          </div>
          <p className="text-[11px] text-[#747C78]">
            {scan.resolvedIp ? `Resolved IP: ${scan.resolvedIp}` : 'No public IP address was resolved'}
          </p>
        </div>
        {scan.modules && (
          <div className="grid grid-cols-2 gap-2 pt-3 sm:grid-cols-3 lg:grid-cols-6">
            {Object.entries(scan.modules).map(([name, module]) => (
              <div key={name} className="rounded-lg border border-[#E2E5E1] bg-[#FAFBF9] p-2">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-[#747C78]">{name}</div>
                <div className="mt-1 text-xs font-bold text-[#202522]">{module.status}</div>
                {'message' in module && module.message && (
                  <p className="mt-1 text-[10px] leading-relaxed text-[#747C78]">{module.message}</p>
                )}
              </div>
            ))}
          </div>
        )}
        {scan.dnsRecords && (
          <div className="mt-3 border-t border-[#E2E5E1] pt-3 text-[11px] text-[#555C57]">
            <strong>Collected DNS records:</strong>{' '}
            {Object.entries(scan.dnsRecords)
              .filter(([, values]) => values.length > 0)
              .map(([type, values]) => `${type}: ${values.map(value => typeof value === 'string' ? value : `${value.priority} ${value.exchange}`).join(', ')}`)
              .join(' · ') || 'No records were returned'}
          </div>
        )}
      </section>

      {/* Sub-Tabs Selector */}
      <InvestigationSubTabs
        activeSubTab={activeSubTab}
        onSelectSubTab={setActiveSubTab}
        findingsCount={scan.findings.length}
      />

      {/* VIEW 1: INVESTIGATION LAB (EXACT MATCH OF DESIGN SCREENSHOT) */}
      {activeSubTab === 'lab' && (
        <div className="flex flex-col lg:flex-row gap-6 items-start">
          {/* Left Column: Flow & Case Summary */}
          <InvestigationFlowSidebar scan={scan} />

          {/* Center Column: Graph + Timeline & Key Evidence */}
          <div className="flex-1 space-y-5 min-w-0">
            {/* Threat Relationship Map */}
            <ThreatRelationshipMap 
              scan={scan} 
              onSelectNodeDetail={(tab) => setActiveSubTab(tab as SubTabType)}
            />

            {/* Bottom 2-Column Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <InvestigationTimeline scan={scan} />
              <KeyEvidenceCard
                scan={scan}
                onViewAllFindings={() => setActiveSubTab('findings')}
              />
            </div>
          </div>

          {/* Right Column: Risk Assessment & Action */}
          <RiskAssessmentPanel scan={scan} />
        </div>
      )}

      {/* VIEW 2: FINDINGS BREAKDOWN */}
      {activeSubTab === 'findings' && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[#E2E5E1]">
            <div>
              <h3 className="text-base font-bold text-[#14231C]">All Correlated Findings ({scan.findings.length})</h3>
              <p className="text-xs text-[#747C78]">Categorized risk findings extracted during automated multi-vector probe</p>
            </div>
          </div>

          <div className="space-y-3">
            {scan.findings.length === 0 && (
              <p className="rounded-xl border border-[#E2E5E1] bg-[#FAFBF9] p-4 text-xs text-[#747C78]">
                No findings were returned by the completed analysis modules.
              </p>
            )}
            {scan.findings.map((f) => (
              <div key={f.id} className="p-4 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider ${
                      f.severity === 'CRITICAL' ? 'bg-[#C93B2B]/10 text-[#C93B2B] border border-[#C93B2B]/20' :
                      f.severity === 'HIGH' ? 'bg-[#E07A2A]/10 text-[#E07A2A] border border-[#E07A2A]/20' :
                      f.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-900' :
                      'bg-emerald-100 text-emerald-800'
                    }`}>
                      {f.severity}
                    </span>
                    <span className="text-xs font-mono text-[#747C78]">[{f.category}]</span>
                    <h4 className="text-xs font-bold text-[#14231C]">{f.title}</h4>
                  </div>
                </div>

                <p className="text-xs text-[#555C57] leading-relaxed">{f.technicalDetails}</p>
                {f.source && <p className="text-[11px] text-[#747C78]">Evidence source: {f.source}</p>}
                <div className="p-2 bg-white rounded-lg border border-[#E2E5E1] font-mono text-[11px] text-[#202522] truncate">
                  Evidence: {f.evidence}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1">
                  <div>
                    <strong className="text-[#C93B2B]">Impact:</strong> <span className="text-[#555C57]">{f.impact}</span>
                  </div>
                  <div>
                    <strong className="text-[#2E7D52]">Remediation:</strong> <span className="text-[#555C57]">{f.remediation}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 3: CERTIFICATE INTELLIGENCE */}
      {activeSubTab === 'certificate' && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-5">
          <div className="flex items-center justify-between pb-4 border-b border-[#E2E5E1]">
            <div>
              <h3 className="text-base font-bold text-[#14231C]">SSL/TLS X.509 Certificate Intelligence</h3>
              <p className="text-xs text-[#747C78]">Socket handshake details and certificate transparency verification</p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-bold font-mono ${
              scan.modules?.tls.status === 'unavailable'
                ? 'bg-neutral-100 text-neutral-700'
                : scan.tlsCertificate.valid
                  ? 'bg-emerald-100 text-emerald-800'
                  : 'bg-red-100 text-red-800'
            }`}>
              {scan.modules?.tls.status === 'unavailable'
                ? 'ANALYSIS UNAVAILABLE'
                : scan.tlsCertificate.valid
                  ? 'VALID CERTIFICATE'
                  : 'INVALID / UNTRUSTED'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-4 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold">Subject</div>
              <div>CN: <strong>{scan.tlsCertificate.subject.commonName || 'N/A'}</strong></div>
              <div>Organization: {scan.tlsCertificate.subject.organization || 'Not Disclosed'}</div>
              <div>Country: {scan.tlsCertificate.subject.country || 'N/A'}</div>
              <div>Hostname Match: <strong>{scan.tlsCertificate.validFrom
                ? scan.tlsCertificate.hostnameMatch ? 'Verified' : 'Mismatch'
                : 'Unavailable'}</strong></div>
            </div>

            <div className="p-4 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold">Issuer Authority</div>
              <div>CA: <strong>{scan.tlsCertificate.issuer.commonName || 'N/A'}</strong></div>
              <div>Issuer Org: {scan.tlsCertificate.issuer.organization || 'N/A'}</div>
              <div>Self-Signed: <strong>{scan.tlsCertificate.isSelfSigned ? 'YES' : 'No'}</strong></div>
              <div>Days Remaining: <strong>{scan.tlsCertificate.validFrom
                ? `${scan.tlsCertificate.daysRemaining} days`
                : 'N/A'}</strong></div>
            </div>

            <div className="p-4 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold">Cryptographic Specs</div>
              <div>Key: <strong>{scan.tlsCertificate.publicKeyAlgorithm && scan.tlsCertificate.keySizeBits
                ? `${scan.tlsCertificate.publicKeyAlgorithm} (${scan.tlsCertificate.keySizeBits} bits)`
                : 'N/A'}</strong></div>
              <div>Cipher: <span className="truncate block">{scan.tlsCertificate.cipher || 'N/A'}</span></div>
              <div>Protocol: {scan.tlsCertificate.protocol || 'N/A'}</div>
              <div>Signature Alg: {scan.tlsCertificate.signatureAlgorithm || 'N/A'}</div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 4: SECURITY HEADERS SCORECARD */}
      {activeSubTab === 'security' && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-5">
          <div className="flex items-center justify-between pb-4 border-b border-[#E2E5E1]">
            <div>
              <h3 className="text-base font-bold text-[#14231C]">HTTP Security Headers Hardening</h3>
              <p className="text-xs text-[#747C78]">Browser perimeter defense and cookie security evaluation</p>
            </div>
            <span className="text-2xl font-bold font-mono text-[#14231C]">
              {scan.modules?.http.status === 'unavailable' ? 'N/A' : `${scan.securityHeaders.overallHeaderScore}/100`}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl">
              <div className="flex justify-between font-bold mb-1">
                <span>Content-Security-Policy (CSP)</span>
                <span className={scan.securityHeaders.csp.present ? 'text-[#2E7D52]' : 'text-[#C93B2B]'}>
                  {scan.securityHeaders.csp.status}
                </span>
              </div>
              <p className="text-[#747C78] text-[11px]">{scan.securityHeaders.csp.notes}</p>
            </div>

            <div className="p-3 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl">
              <div className="flex justify-between font-bold mb-1">
                <span>Strict-Transport-Security (HSTS)</span>
                <span className={scan.securityHeaders.hsts.present ? 'text-[#2E7D52]' : 'text-[#C93B2B]'}>
                  {scan.securityHeaders.hsts.status}
                </span>
              </div>
              <p className="text-[#747C78] text-[11px]">{scan.securityHeaders.hsts.notes}</p>
            </div>

            <div className="p-3 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl">
              <div className="flex justify-between font-bold mb-1">
                <span>X-Frame-Options (Clickjacking)</span>
                <span className={scan.securityHeaders.xFrameOptions.present ? 'text-[#2E7D52]' : 'text-[#C93B2B]'}>
                  {scan.securityHeaders.xFrameOptions.status}
                </span>
              </div>
              <p className="text-[#747C78] text-[11px]">{scan.securityHeaders.xFrameOptions.notes}</p>
            </div>

            <div className="p-3 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl">
              <div className="flex justify-between font-bold mb-1">
                <span>X-Content-Type-Options (MIME)</span>
                <span className={scan.securityHeaders.xContentTypeOptions.status === 'GOOD' ? 'text-[#2E7D52]' : 'text-[#E07A2A]'}>
                  {scan.securityHeaders.xContentTypeOptions.status}
                </span>
              </div>
              <p className="text-[#747C78] text-[11px]">{scan.securityHeaders.xContentTypeOptions.notes}</p>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 5: THREAT INTEL */}
      {activeSubTab === 'threat-intel' && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[#E2E5E1]">
            <div>
              <h3 className="text-base font-bold text-[#14231C]">Threat Intelligence Telemetry</h3>
              <p className="text-xs text-[#747C78]">Correlated Indicators of Compromise (IoCs) and community alerts</p>
            </div>
            <button
              onClick={onOpenReportModal}
              className="px-3.5 py-1.5 bg-[#14231C] text-white rounded-xl text-xs font-semibold"
            >
              Report IoC
            </button>
          </div>

          <div className="space-y-3">
            {scan.threatIntelMatches.length === 0 && (
              <p className="rounded-xl border border-[#E2E5E1] bg-[#FAFBF9] p-4 text-xs text-[#747C78]">
                {scan.modules?.threatIntel.message || 'No matching community reports were returned.'}
              </p>
            )}
            {scan.threatIntelMatches.map((m, i) => (
              <div key={i} className="p-4 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl flex items-center justify-between text-xs">
                <div>
                  <div className="font-bold text-[#14231C] text-sm">{m.source}</div>
                  <div className="text-[11px] text-[#747C78] font-mono mt-0.5">Matched Entity: {m.matchedValue}</div>
                  <div className="flex gap-1.5 mt-2">
                    {m.tags.map((t, ti) => (
                      <span key={ti} className="px-2 py-0.5 bg-neutral-200 rounded text-[10px] font-mono">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="text-right font-mono">
                  <div className="text-lg font-bold text-[#C93B2B]">{m.confidence}%</div>
                  <div className="text-[10px] text-[#747C78] uppercase">Confidence</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 6: RAW DATA */}
      {activeSubTab === 'raw-data' && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-[#14231C]">Structured Scan JSON Output</h3>
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FAFBF9] hover:bg-neutral-100 border border-[#D5DAD3] rounded-xl text-xs font-mono font-medium text-[#14231C] transition-colors"
            >
              {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedJson ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>
          <pre className="p-4 bg-[#14231C] text-emerald-400 font-mono text-xs rounded-xl overflow-x-auto max-h-[500px]">
            {JSON.stringify(scan, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
