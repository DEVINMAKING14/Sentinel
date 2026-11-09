import React from 'react';
import { Plus, Bell, ShieldAlert } from 'lucide-react';

interface HeaderProps {
  onQuickScan: () => void;
  openThreatsCount: number;
}

export const Header: React.FC<HeaderProps> = ({ onQuickScan, openThreatsCount }) => {
  return (
    <header className="px-8 pt-8 pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#E2E5E1]/60">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-[#202522]">
            Welcome back, Shafayet <span role="img" aria-label="wave">👋</span>
          </h1>
        </div>
        <p className="text-xs text-[#747C78] mt-1 max-w-2xl">
          The dashboard is where you can analyze remediation efficacy and stay up-to-date on potential attack surface.
        </p>
      </div>

      <div className="flex items-center gap-4 shrink-0">
        <button
          onClick={onQuickScan}
          className="flex items-center gap-2 px-4 py-2 bg-[#202522] text-white text-xs font-semibold rounded-xl hover:bg-[#323935] transition-all shadow-sm active:scale-98"
        >
          <Plus className="w-4 h-4 stroke-[2.5]" />
          <span>New Scan</span>
        </button>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-white border border-[#E2E5E1] rounded-xl text-xs font-medium text-[#555C57] shadow-sm">
          <span className="text-[#747C78]">Testing status:</span>
          <span className="flex items-center gap-1.5 text-emerald-700 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            Active
          </span>
        </div>

        <button 
          title="Threat alerts"
          className="relative w-9 h-9 rounded-xl bg-white border border-[#E2E5E1] flex items-center justify-center text-[#555C57] hover:text-[#202522] transition-colors shadow-sm"
        >
          <Bell className="w-4 h-4" />
          {openThreatsCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-[#B42318] text-white text-[9px] font-bold rounded-full flex items-center justify-center">
              {openThreatsCount > 9 ? '9+' : openThreatsCount}
            </span>
          )}
        </button>

        <div className="w-9 h-9 rounded-xl bg-[#202522] border border-[#202522] overflow-hidden flex items-center justify-center text-white text-xs font-bold font-mono shadow-sm">
          SH
        </div>
      </div>
    </header>
  );
};
