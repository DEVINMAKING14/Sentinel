import React, { useState } from 'react';
import { GlobeLock, Search, ShieldCheck, ShieldAlert, Key, Calendar, Server, Info, AlertTriangle } from 'lucide-react';
import { TlsCertificateAnalysis } from '../types';

export const CertificatesView: React.FC = () => {
  const [domainInput, setDomainInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [certData, setCertData] = useState<TlsCertificateAnalysis | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleQuery = async (domain: string) => {
    if (!domain.trim()) return;
    setLoading(true);
    setCertData(null);
    setErrorMsg(null);
    try {
      const cleanDomain = domain.replace(/^https?:\/\//i, '').split('/')[0].trim();
      const res = await fetch(`/api/v1/certificates/${encodeURIComponent(cleanDomain)}`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.details || data.error || 'Certificate inspection failed.');
      }
      if (data.certificate?.validFrom) {
        setCertData(data.certificate);
      } else {
        setErrorMsg(data.certificate?.notes?.[0] || 'No certificate was retrieved for this hostname.');
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Network error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <div className="flex items-center gap-2 mb-1">
          <GlobeLock className="w-5 h-5 text-[#426B57]" />
          <h2 className="text-lg font-bold text-[#202522]">SSL/TLS Certificate Intelligence Engine</h2>
        </div>
        <p className="text-xs text-[#747C78] mb-5">
          Real-time socket inspection of public X.509 certificates, Subject Alternative Names (SANs), key size, cipher suites, and root authority chains.
        </p>

        {/* Input Form */}
        <form 
          onSubmit={(e) => { e.preventDefault(); handleQuery(domainInput); }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-3 text-[#747C78]" />
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="Enter domain for TLS socket probe (e.g., github.com, badssl.com)..."
              className="w-full pl-10 pr-4 py-2.5 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl text-xs font-mono text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !domainInput.trim()}
            className="px-6 py-2.5 bg-[#202522] hover:bg-[#323935] disabled:opacity-50 text-white text-xs font-semibold rounded-xl flex items-center justify-center gap-2 transition-all shadow-sm"
          >
            {loading ? 'Inspecting Socket...' : 'Inspect TLS Certificate'}
          </button>
        </form>

      </div>

      {errorMsg && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700">
          {errorMsg}
        </div>
      )}

      {/* Certificate Details */}
      {certData && (
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-100 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider ${
                  certData.valid ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                }`}>
                  {certData.valid ? 'VALID CERTIFICATE' : 'REVOKED / UNTRUSTED'}
                </span>
                <span className="text-xs font-mono text-[#747C78]">Trust Score: {certData.trustScore}/100</span>
              </div>
              <h3 className="text-lg font-bold font-mono text-[#202522] mt-1">
                {certData.subject.commonName || 'X.509 Peer Certificate'}
              </h3>
            </div>

            <div className="text-right font-mono text-xs">
              <span className="text-[#747C78]">Expires in:</span>{' '}
              <strong className={certData.isExpired ? 'text-red-700' : 'text-emerald-700'}>
                {certData.daysRemaining} days
              </strong>
            </div>
          </div>

          {/* Key Specs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-4 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-[#426B57]" />
                <span>Subject & Domain</span>
              </div>
              <div>CN: <strong>{certData.subject.commonName || 'N/A'}</strong></div>
              <div>Organization: {certData.subject.organization || 'Not Disclosed'}</div>
              <div>Country: {certData.subject.country || 'N/A'}</div>
              <div>Hostname Match: <strong>{certData.hostnameMatch ? 'Verified' : 'Mismatch'}</strong></div>
            </div>

            <div className="p-4 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-[#426B57]" />
                <span>Issuer & Trust Root</span>
              </div>
              <div>CA: <strong>{certData.issuer.commonName || 'N/A'}</strong></div>
              <div>Issuer Org: {certData.issuer.organization || 'N/A'}</div>
              <div>Self-Signed: <strong>{certData.isSelfSigned ? 'YES (Untrusted)' : 'No (Public CA)'}</strong></div>
              <div>Protocol: {certData.protocol || 'TLS'}</div>
            </div>

            <div className="p-4 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl space-y-2">
              <div className="text-[#747C78] font-sans font-bold flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-[#426B57]" />
                <span>Cryptographic Parameters</span>
              </div>
              <div>Public Key: <strong>{certData.publicKeyAlgorithm || 'RSA'}</strong></div>
              <div>Key Length: <strong>{certData.keySizeBits ? `${certData.keySizeBits} bits` : 'Standard'}</strong></div>
              <div>Cipher: <span className="truncate block">{certData.cipher || 'Standard'}</span></div>
              <div>Signature Alg: {certData.signatureAlgorithm || 'sha256'}</div>
            </div>
          </div>

          {/* Subject Alternative Names (SANs) */}
          {certData.subjectAltNames.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-[#202522] mb-2 font-mono">
                Subject Alternative Names ({certData.subjectAltNames.length} SANs Registered):
              </h4>
              <div className="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto p-3 bg-neutral-50 rounded-xl border border-[#E2E5E1]">
                {certData.subjectAltNames.map((san, i) => (
                  <span key={i} className="px-2 py-0.5 bg-white border border-[#E2E5E1] rounded text-[11px] font-mono text-[#555C57]">
                    {san}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Educational Callout */}
          <div className="p-4 bg-amber-50/70 border border-amber-200 rounded-xl text-xs text-amber-900 flex items-start gap-2.5">
            <Info className="w-4 h-4 text-amber-700 mt-0.5 shrink-0" />
            <div>
              <strong>Security Analyst Note on Phishing & SSL:</strong>
              <p className="mt-0.5 text-amber-800">
                Over 80% of active phishing websites now utilize valid SSL/TLS certificates issued by free, automated authorities (such as Let's Encrypt or Cloudflare). Transport layer encryption guarantees that traffic is encrypted in transit, but offers zero cryptographic guarantee regarding whether the remote server belongs to a benign or malicious entity.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
