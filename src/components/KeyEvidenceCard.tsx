import React from 'react';
import { 
  FolderOpen, 
  AlertTriangle, 
  FileText, 
  ArrowLeftRight, 
  ChevronRight,
  ShieldAlert
} from 'lucide-react';
import { ScanResult, Finding } from '../types';

interface KeyEvidenceCardProps {
  scan: ScanResult;
  onViewAllFindings: () => void;
}

export const KeyEvidenceCard: React.FC<KeyEvidenceCardProps> = ({
  scan,
  onViewAllFindings,
}) => {
  const domain = scan.domain;

  // Build dynamic evidence list from scan findings if available
  const sortedFindings = [...scan.findings].sort((a, b) => {
    const weights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (weights[b.severity] || 0) - (weights[a.severity] || 0);
  });

  const evidenceList = sortedFindings.slice(0, 3).map((f, idx) => {
        const isCriticalOrHigh = f.severity === 'CRITICAL' || f.severity === 'HIGH';
        const isMedium = f.severity === 'MEDIUM';

        let Icon = AlertTriangle;
        if (f.category === 'PHISHING') Icon = FileText;
        else if (f.category === 'REDIRECTION') Icon = ArrowLeftRight;
        else if (f.category === 'SSL_TLS') Icon = ShieldAlert;

        return {
          id: `f-${f.id || idx}`,
          icon: Icon,
          iconColor: isCriticalOrHigh ? 'text-[#C93B2B]' : isMedium ? 'text-[#E07A2A]' : 'text-[#2E7D52]',
          iconBg: isCriticalOrHigh ? 'bg-[#FDE8E6]' : isMedium ? 'bg-[#FEF4E8]' : 'bg-[#E2F2E9]',
          title: f.title,
          subtitle: f.evidence || f.technicalDetails,
          severity: f.severity.charAt(0) + f.severity.slice(1).toLowerCase(),
          severityColor: isCriticalOrHigh 
            ? 'bg-[#FDE8E6] text-[#C93B2B] border border-[#F7D2CD]' 
            : isMedium 
            ? 'bg-[#FEF4E8] text-[#E07A2A] border border-[#F5DCBE]' 
            : 'bg-[#E2F2E9] text-[#2E7D52] border border-[#B5D8C3]',
        };
      });

  return (
    <div className="bg-white border border-[#E2E5E1] rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <FolderOpen className="w-4 h-4 text-[#747C78]" />
          <h3 className="text-sm font-bold text-[#14231C]">Key Evidence</h3>
        </div>
        <button
          onClick={onViewAllFindings}
          className="text-xs font-semibold text-[#14231C] hover:text-[#2E7D52] flex items-center gap-1 transition-colors"
        >
          <span>View All</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="space-y-2.5 my-auto">
        {evidenceList.length === 0 && (
          <p className="rounded-xl border border-[#E2E5E1] bg-[#FAFBF9] p-3 text-xs text-[#747C78]">
            No findings were returned. Missing findings do not verify that this website is safe.
          </p>
        )}
        {evidenceList.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              className="p-3 bg-[#FAFBF9] border border-[#E2E5E1] rounded-xl flex items-center justify-between gap-3 hover:bg-neutral-50 transition-colors"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className={`w-8 h-8 rounded-lg ${item.iconBg} flex items-center justify-center ${item.iconColor} shrink-0`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-bold text-[#14231C] truncate">{item.title}</div>
                  <div className="text-[11px] text-[#747C78] truncate font-mono mt-0.5">{item.subtitle}</div>
                </div>
              </div>

              <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${item.severityColor} shrink-0`}>
                {item.severity}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
