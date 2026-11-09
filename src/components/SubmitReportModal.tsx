import React, { useState } from 'react';
import { X, ShieldAlert, Send } from 'lucide-react';

interface SubmitReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (report: {
    url: string;
    domain: string;
    threatType: 'PHISHING' | 'MALWARE' | 'BRAND_IMPERSONATION' | 'CREDENTIAL_HARVESTING' | 'PAYMENT_FRAUD';
    targetedBrand?: string;
    evidenceNotes: string;
    submittedBy: string;
  }) => Promise<void>;
  initialUrl?: string;
  initialDomain?: string;
}

export const SubmitReportModal: React.FC<SubmitReportModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  initialUrl = '',
  initialDomain = '',
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [threatType, setThreatType] = useState<'PHISHING' | 'MALWARE' | 'BRAND_IMPERSONATION' | 'CREDENTIAL_HARVESTING' | 'PAYMENT_FRAUD'>('PHISHING');
  const [targetedBrand, setTargetedBrand] = useState('');
  const [evidenceNotes, setEvidenceNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || !evidenceNotes.trim()) return;

    let parsedDomain = initialDomain;
    try {
      const u = new URL(url.startsWith('http') ? url : `https://${url}`);
      parsedDomain = u.hostname;
    } catch {
      parsedDomain = url.split('/')[0];
    }

    setSubmitting(true);
    try {
      await onSubmit({
        url: url.trim(),
        domain: parsedDomain,
        threatType,
        targetedBrand: targetedBrand.trim() || undefined,
        evidenceNotes: evidenceNotes.trim(),
        submittedBy: 'analyst_active_session',
      });
      onClose();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
      <div className="bg-white border border-[#E2E5E1] rounded-2xl w-full max-w-lg shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="px-6 py-4 border-b border-[#E2E5E1] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-[#B42318]" />
            <h3 className="text-sm font-bold text-[#202522]">Submit Threat Evidence to Community Exchange</h3>
          </div>
          <button onClick={onClose} className="text-[#747C78] hover:text-[#202522]">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          <div>
            <label className="block font-bold text-[#202522] mb-1">Target Suspicious URL *</label>
            <input
              type="text"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. http://paypa1-security.example.com/login"
              className="w-full px-3 py-2 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl font-mono text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-bold text-[#202522] mb-1">Threat Classification *</label>
              <select
                value={threatType}
                onChange={(e) => setThreatType(e.target.value as any)}
                className="w-full px-3 py-2 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
              >
                <option value="PHISHING">Phishing Lure</option>
                <option value="BRAND_IMPERSONATION">Brand Impersonation / Typosquatting</option>
                <option value="CREDENTIAL_HARVESTING">Credential Harvesting Kit</option>
                <option value="PAYMENT_FRAUD">Payment / Carding Fraud</option>
                <option value="MALWARE">Malware Distribution Endpoint</option>
              </select>
            </div>

            <div>
              <label className="block font-bold text-[#202522] mb-1">Targeted Brand / Entity</label>
              <input
                type="text"
                value={targetedBrand}
                onChange={(e) => setTargetedBrand(e.target.value)}
                placeholder="e.g. PayPal, Microsoft, Chase"
                className="w-full px-3 py-2 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
              />
            </div>
          </div>

          <div>
            <label className="block font-bold text-[#202522] mb-1">Evidence & Technical Details *</label>
            <textarea
              required
              rows={3}
              value={evidenceNotes}
              onChange={(e) => setEvidenceNotes(e.target.value)}
              placeholder="Describe attack indicators: homoglyphs, AiTM reverse-proxy, credential fields, fake domain registration, phishing lure text..."
              className="w-full px-3 py-2 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl text-[#202522] focus:outline-hidden focus:ring-2 focus:ring-[#426B57]/30"
            />
          </div>

          <div className="pt-2 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-[#747C78] hover:text-[#202522] font-semibold"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !url.trim() || !evidenceNotes.trim()}
              className="px-5 py-2 bg-[#202522] hover:bg-[#323935] disabled:opacity-50 text-white font-semibold rounded-xl flex items-center gap-2 shadow-sm"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{submitting ? 'Submitting IoC...' : 'Publish to Exchange'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
