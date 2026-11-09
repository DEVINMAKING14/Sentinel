import React from 'react';
import { 
  CheckCircle2, 
  Circle, 
  Calendar, 
  Hourglass, 
  Layers, 
  Globe, 
  MapPin 
} from 'lucide-react';
import { ScanResult } from '../types';

interface InvestigationFlowSidebarProps {
  scan: ScanResult;
}

export const InvestigationFlowSidebar: React.FC<InvestigationFlowSidebarProps> = ({ scan }) => {
  const steps = [
    { title: 'DNS resolution', status: scan.modules?.dns.status || 'unavailable' },
    { title: 'HTTP response and content', status: scan.modules?.http.status || 'unavailable' },
    { title: 'Security assessment', status: scan.modules?.http.status || 'unavailable' },
    { title: 'TLS certificate', status: scan.modules?.tls.status || 'unavailable' },
    { title: 'Threat intelligence', status: scan.modules?.threatIntel.status || 'unavailable' },
    { title: 'Risk synthesis', status: 'completed' },
  ];

  const scannedAt = new Date(scan.timestamp).toLocaleString();
  const durationSec = (scan.scanDurationMs / 1000).toFixed(1) + ' s';
  const serverTech = scan.securityHeaders.serverHeader || 'Not disclosed';
  const ip = scan.resolvedIp || 'Unavailable';

  return (
    <div className="w-full lg:w-56 shrink-0 space-y-6 select-none">
      {/* 1. Investigation Flow Steps */}
      <div className="space-y-3">
        <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#14231C] font-mono">
          Investigation Flow
        </h3>

        <div className="relative pl-1">
          {/* Vertical connecting line */}
          <div className="absolute left-[13px] top-3 bottom-3 w-[1.5px] bg-[#D5DAD3]" />

          <div className="space-y-4">
            {steps.map((step, idx) => (
              <div key={idx} className="relative flex items-center gap-3">
                <div className={`relative z-10 w-6 h-6 rounded-full bg-[#FAFBF9] border flex items-center justify-center ${
                  step.status === 'completed' ? 'border-[#B5D8C3] text-[#2E7D52]' : 'border-[#D5DAD3] text-[#747C78]'
                }`}>
                  {step.status === 'completed' ? (
                    <CheckCircle2 className="w-4 h-4 fill-[#2E7D52] text-white" />
                  ) : (
                    <Circle className="w-3.5 h-3.5 text-[#747C78]" />
                  )}
                </div>
                <span className="text-xs font-medium text-[#14231C]">
                  {step.title} <span className="text-[10px] text-[#747C78]">({step.status})</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="w-full h-[1px] bg-[#E2E5E1]" />

      {/* 2. Case Summary */}
      <div className="space-y-4">
        <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#14231C] font-mono">
          Case Summary
        </h3>

        <div className="space-y-3.5 text-xs">
          {/* Scanned At */}
          <div className="flex items-start gap-2.5">
            <Calendar className="w-4 h-4 text-[#747C78] mt-0.5 shrink-0" />
            <div>
              <div className="text-[11px] text-[#747C78]">Scanned At</div>
              <div className="text-xs font-medium text-[#14231C] font-mono mt-0.5">{scannedAt}</div>
            </div>
          </div>

          {/* Analysis Time */}
          <div className="flex items-start gap-2.5">
            <Hourglass className="w-4 h-4 text-[#747C78] mt-0.5 shrink-0" />
            <div>
              <div className="text-[11px] text-[#747C78]">Analysis Time</div>
              <div className="text-xs font-medium text-[#14231C] font-mono mt-0.5">{durationSec}</div>
            </div>
          </div>

          {/* Tech Stack */}
          <div className="flex items-start gap-2.5">
            <Layers className="w-4 h-4 text-[#747C78] mt-0.5 shrink-0" />
            <div>
              <div className="text-[11px] text-[#747C78]">Tech Stack</div>
              <div className="text-xs font-medium text-[#14231C] font-mono mt-0.5">{serverTech}</div>
            </div>
          </div>

          {/* IP Address */}
          <div className="flex items-start gap-2.5">
            <Globe className="w-4 h-4 text-[#747C78] mt-0.5 shrink-0" />
            <div>
              <div className="text-[11px] text-[#747C78]">IP Address</div>
              <div className="text-xs font-medium text-[#14231C] font-mono mt-0.5">{ip}</div>
            </div>
          </div>

          {/* Hosting */}
          <div className="flex items-start gap-2.5">
            <MapPin className="w-4 h-4 text-[#747C78] mt-0.5 shrink-0" />
            <div>
              <div className="text-[11px] text-[#747C78]">Hosting</div>
              <div className="text-xs font-medium text-[#14231C] mt-0.5 truncate max-w-[170px]">
                {scan.hostingProvider || 'Unavailable'} {scan.asn ? `(${scan.asn})` : ''}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
