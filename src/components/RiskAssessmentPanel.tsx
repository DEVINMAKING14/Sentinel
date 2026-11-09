import React from 'react';
import { ShieldCheck, AlertTriangle } from 'lucide-react';
import { ScanResult } from '../types';

interface RiskAssessmentPanelProps {
  scan: ScanResult;
}

export const RiskAssessmentPanel: React.FC<RiskAssessmentPanelProps> = ({ scan }) => {
  const score = scan.riskScore;
  const isHighRisk = score >= 70;
  const isMediumRisk = score >= 40 && score < 70;
  const isSafe = score < 40;

  // Gauge calculation: Arc from 180 to 0 degrees (left to right)
  const radius = 75;
  const circumference = Math.PI * radius; // Half-circle
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const summaryText = scan.aiAssessment?.analystSummary
    ? scan.aiAssessment.analystSummary
    : isHighRisk
    ? `The available evidence produced an elevated risk score. Review the findings and module status before drawing conclusions.`
    : isMediumRisk
    ? `Some observed signals indicate risk. This assessment does not establish the website owner's identity.`
    : `Low observed indicators in the evidence collected; this is not a safety or legitimacy verification.`;

  const recommendation = scan.recommendations[0] || 'Review the collected evidence and verify the site through an independently trusted source.';

  return (
    <div className="w-full lg:w-72 shrink-0 space-y-4">
      {/* 1. Risk Assessment Card */}
      <div className="bg-white border border-[#E2E5E1] rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        {/* Header */}
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck className="w-4 h-4 text-[#14231C]" />
          <h3 className="text-sm font-bold text-[#14231C]">Risk Assessment</h3>
        </div>

        {/* Semi-circular Gauge Chart */}
        <div className="relative flex flex-col items-center justify-center my-3">
          <svg viewBox="0 0 180 100" className="w-44 h-26">
            {/* Background Arc */}
            <path
              d="M 15 90 A 75 75 0 0 1 165 90"
              fill="none"
              stroke="#F4F5F1"
              strokeWidth="14"
              strokeLinecap="round"
            />
            {/* Active Colored Arc */}
            <path
              d="M 15 90 A 75 75 0 0 1 165 90"
              fill="none"
              stroke={score >= 75 ? '#C93B2B' : score >= 50 ? '#E07A2A' : '#2E7D52'}
              strokeWidth="14"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              className="transition-all duration-700 ease-out"
            />
          </svg>

          {/* Value in Center */}
          <div className="absolute bottom-2 flex flex-col items-center">
            <div className="flex items-baseline gap-0.5">
              <span className="text-3xl font-extrabold font-mono text-[#14231C] tracking-tight">
                {score}
              </span>
              <span className="text-xs font-mono text-[#747C78]">/ 100</span>
            </div>

            {/* Pill Badge */}
            <div className="mt-1">
              <span className={`px-3 py-0.5 rounded-full text-[10px] font-bold tracking-wider font-mono uppercase ${
                score >= 75
                  ? 'bg-[#C93B2B]/15 text-[#C93B2B]'
                  : score >= 50
                  ? 'bg-[#E07A2A]/15 text-[#E07A2A]'
                  : 'bg-[#2E7D52]/15 text-[#2E7D52]'
              }`}>
                {scan.riskCategory === 'SAFE' ? 'LOW OBSERVED RISK' : `${scan.riskCategory} RISK`}
              </span>
              <div className="mt-1 text-[10px] text-[#747C78]">
                Evidence coverage: {scan.confidenceScore}%
              </div>
            </div>
          </div>
        </div>

        {/* Summary Description */}
        <p className="text-xs text-center text-[#555C57] my-4 leading-relaxed">
          {summaryText}
        </p>

        {/* 4 Dimensional Weighted Breakdown Bars */}
        <div className="space-y-3 pt-3 border-t border-[#E2E5E1]/60 text-xs">
          {/* Phishing Indicators */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <span className="text-[#555C57]">Phishing Indicators</span>
              <span className="font-mono font-bold text-[#14231C]">
                {scan.dimensionalScores.phishingScore}%
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#F4F5F1] rounded-full overflow-hidden">
              <div 
                className="h-full bg-[#C93B2B] rounded-full" 
                style={{ width: `${scan.dimensionalScores.phishingScore}%` }} 
              />
            </div>
          </div>

          {/* Threat Intelligence */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <span className="text-[#555C57]">Threat Intelligence</span>
              <span className="font-mono font-bold text-[#14231C]">
                {scan.dimensionalScores.threatIntelScore}%
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#F4F5F1] rounded-full overflow-hidden">
              <div 
                className="h-full bg-[#C93B2B] rounded-full" 
                style={{ width: `${scan.dimensionalScores.threatIntelScore}%` }} 
              />
            </div>
          </div>

          {/* Certificate & TLS */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <span className="text-[#555C57]">Certificate & TLS</span>
              <span className="font-mono font-bold text-[#14231C]">
                {scan.modules?.tls.status === 'unavailable' ? 'N/A' : `${scan.dimensionalScores.tlsTrustScore}%`}
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#F4F5F1] rounded-full overflow-hidden">
              <div 
                className="h-full bg-[#E07A2A]/80 rounded-full" 
                style={{ width: `${scan.dimensionalScores.tlsTrustScore}%` }} 
              />
            </div>
          </div>

          {/* Website Security */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <span className="text-[#555C57]">Website Security</span>
              <span className="font-mono font-bold text-[#14231C]">
                {scan.modules?.http.status === 'unavailable' ? 'N/A' : `${scan.dimensionalScores.securityHeadersScore}%`}
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#F4F5F1] rounded-full overflow-hidden">
              <div 
                className="h-full bg-[#E07A2A]/80 rounded-full" 
                style={{ width: `${scan.dimensionalScores.securityHeadersScore}%` }} 
              />
            </div>
          </div>
        </div>
      </div>

      {/* 2. Recommended Action Box */}
      <div className={`border rounded-2xl p-5 shadow-xs ${
        isSafe
          ? 'bg-[#F1F8F4] border-[#B5D8C3]'
          : isMediumRisk
          ? 'bg-[#FFFDF9] border-[#E7C79A]'
          : 'bg-[#FFF5F4] border-[#F7D2CD]'
      }`}>
        <div className={`flex items-center gap-2 font-bold text-xs mb-2 ${
          isSafe ? 'text-[#2E7D52]' : isMediumRisk ? 'text-[#E07A2A]' : 'text-[#C93B2B]'
        }`}>
          {isSafe ? <ShieldCheck className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          <span>Recommended Action</span>
        </div>
        <p className="text-xs text-[#14231C] leading-relaxed">
          {recommendation}
        </p>
      </div>
    </div>
  );
};
