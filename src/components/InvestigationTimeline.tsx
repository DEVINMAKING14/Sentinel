import React from 'react';
import { Info } from 'lucide-react';
import { ScanResult } from '../types';

interface InvestigationTimelineProps {
  scan: ScanResult;
}

export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({ scan }) => {
  const events = scan.timelineEvents || [];

  return (
    <div className="bg-white border border-[#E2E5E1] rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] h-full flex flex-col justify-between">
      <div className="flex items-center gap-2 mb-4">
        <Info className="w-4 h-4 text-[#747C78]" />
        <h3 className="text-sm font-bold text-[#14231C]">Investigation Timeline</h3>
      </div>

      <div className="relative pl-2 space-y-3.5 my-auto">
        {/* Continuous vertical connecting line */}
        <div className="absolute left-[11px] top-2 bottom-2 w-[1.5px] bg-[#E2E5E1]" />

        {events.length === 0 && <p className="text-xs text-[#747C78]">No timeline events were returned.</p>}
        {events.map((ev, i) => (
          <div key={i} className="relative flex items-center gap-3 text-xs">
            <span className={`relative z-10 w-2.5 h-2.5 rounded-full ring-4 ring-white shrink-0 ${
              ev.status === 'alert' ? 'bg-[#C93B2B]' : ev.status === 'info' ? 'bg-[#A2A9A4]' : 'bg-[#2E7D52]'
            }`} />
            <span className="font-mono text-[#747C78] text-[11px]">{ev.timestamp}</span>
            <span className={`truncate font-medium ${
              ev.status === 'alert' ? 'text-[#14231C] font-semibold' : 'text-[#555C57]'
            }`}>
              {ev.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
