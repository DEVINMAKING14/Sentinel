import React from 'react';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  History, 
  FileText, 
  Crosshair, 
  BrainCircuit, 
  GlobeLock, 
  Radio, 
  Settings, 
  Layers
} from 'lucide-react';
import { ActiveTab } from '../types';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  openFindingsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  openFindingsCount,
}) => {
  return (
    <aside className="w-64 bg-[#F7F7F4] border-r border-[#E2E5E1] flex flex-col justify-between shrink-0 select-none min-h-screen">
      <div className="p-5">
        {/* Brand Lockup */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl bg-[#202522] flex items-center justify-center text-white shadow-sm">
            <ShieldCheck className="w-5 h-5 text-emerald-400 stroke-[2.2]" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-tight text-[#202522]">SENTINEL</div>
            <div className="text-[11px] text-[#747C78] font-mono tracking-wide">THREAT & TRUST OS</div>
          </div>
        </div>

        {/* Section 1: Reporting */}
        <div className="mb-6">
          <div className="flex items-center justify-between px-3 py-1 text-[11px] font-semibold text-[#747C78] uppercase tracking-wider">
            <span>Reporting</span>
          </div>
          <div className="mt-1.5 space-y-0.5">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center gap-3 px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'dashboard'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <LayoutDashboard className="w-4 h-4 text-[#747C78]" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`w-full flex items-center gap-3 px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'history'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <History className="w-4 h-4 text-[#747C78]" />
              <span>Audit History</span>
            </button>

            <button
              onClick={() => setActiveTab('threat-intel')}
              className={`w-full flex items-center justify-between px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'threat-intel'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <div className="flex items-center gap-3">
                <FileText className="w-4 h-4 text-[#747C78]" />
                <span>Threat Feeds</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#426B57]/10 text-[#426B57] rounded-md font-semibold">6 Live</span>
            </button>
          </div>
        </div>

        {/* Section 2: Threat Detection */}
        <div className="mb-6">
          <div className="flex items-center justify-between px-3 py-1 text-[11px] font-semibold text-[#747C78] uppercase tracking-wider">
            <span>Threat Intelligence</span>
          </div>
          <div className="mt-1.5 space-y-0.5">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`w-full flex items-center justify-between px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'scanner'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <div className="flex items-center gap-3">
                <Crosshair className="w-4 h-4 text-[#D97706]" />
                <span>Live URL Scanner</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-700 rounded-md font-semibold">Ready</span>
            </button>

            <button
              onClick={() => setActiveTab('threat-intel')}
              className={`w-full flex items-center justify-between px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'threat-intel'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <div className="flex items-center gap-3">
                <Radio className="w-4 h-4 text-[#747C78]" />
                <span>IoC Community</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-red-500/10 text-red-700 rounded-md font-semibold">
                {openFindingsCount} Active
              </span>
            </button>

            <button
              onClick={() => setActiveTab('certificates')}
              className={`w-full flex items-center gap-3 px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'certificates'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <GlobeLock className="w-4 h-4 text-[#747C78]" />
              <span>TLS / SSL Analysis</span>
            </button>
          </div>
        </div>

        {/* Section 3: Attack Surface & Governance */}
        <div className="mb-6">
          <div className="flex items-center justify-between px-3 py-1 text-[11px] font-semibold text-[#747C78] uppercase tracking-wider">
            <span>Security Operations</span>
          </div>
          <div className="mt-1.5 space-y-0.5">
            <button
              onClick={() => setActiveTab('scanner')}
              className="w-full flex items-center justify-between px-3.5 py-2 text-xs font-medium rounded-xl text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03] transition-all"
            >
              <div className="flex items-center gap-3">
                <BrainCircuit className="w-4 h-4 text-[#747C78]" />
                <span>AI Threat Vectoring</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-emerald-500/10 text-emerald-800 rounded-md">Gemini</span>
            </button>

            <button
              onClick={() => setActiveTab('settings')}
              className={`w-full flex items-center gap-3 px-3.5 py-2 text-xs font-medium rounded-xl transition-all ${
                activeTab === 'settings'
                  ? 'bg-white text-[#202522] shadow-[0_1px_3px_rgba(0,0,0,0.06)] border border-[#E2E5E1]'
                  : 'text-[#555C57] hover:text-[#202522] hover:bg-black/[0.03]'
              }`}
            >
              <Settings className="w-4 h-4 text-[#747C78]" />
              <span>SSRF & Engine Config</span>
            </button>
          </div>
        </div>
      </div>

      {/* Footer Profile Box */}
      <div className="p-4 m-3 border border-[#E2E5E1] rounded-2xl bg-white/70">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-[#202522] text-white flex items-center justify-center font-mono text-xs font-bold">
              NS
            </div>
            <div>
              <div className="text-xs font-semibold text-[#202522]">Shafayet / Analyst</div>
              <div className="text-[10px] text-[#747C78]">Lead Threat Hunter</div>
            </div>
          </div>
          <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
        </div>
      </div>
    </aside>
  );
};
