import React from 'react';
import { 
  Compass, 
  Search, 
  Layers, 
  ShieldCheck, 
  BarChart2, 
  Users, 
  Bell,
  Sparkles
} from 'lucide-react';

export type TopNavTab = 'investigate' | 'intelligence' | 'certificates' | 'reports' | 'community';

interface TopNavProps {
  activeTab: TopNavTab;
  onSelectTab: (tab: TopNavTab) => void;
  openThreatsCount: number;
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  onSelectTab,
  openThreatsCount,
}) => {
  return (
    <header className="relative w-full bg-[#F4F5F1] border-b border-[#E2E5E1] px-6 py-2.5 flex items-center justify-between select-none z-20">
      {/* Subtle topographic contour overlay */}
      <div className="absolute inset-0 bg-topographic opacity-40 pointer-events-none" />

      {/* Left: Brand Badge */}
      <div className="relative flex items-center gap-3 z-10">
        <div className="flex items-center gap-2.5 px-4 py-2 bg-[#14231C] text-white rounded-r-2xl rounded-l-md shadow-xs">
          <Compass className="w-5 h-5 text-emerald-400 stroke-[2.2]" />
          <div>
            <div className="text-xs font-bold tracking-wider font-mono text-white">SENTINEL</div>
            <div className="text-[10px] text-[#8EA297] font-sans -mt-0.5 tracking-tight">Web Observatory</div>
          </div>
        </div>
      </div>

      {/* Center: Main Navigation Tabs */}
      <nav className="relative hidden md:flex items-center gap-1.5 z-10">
        <button
          onClick={() => onSelectTab('investigate')}
          className={`flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${
            activeTab === 'investigate'
              ? 'bg-white text-[#14231C] shadow-xs border border-[#D5DAD3]'
              : 'text-[#616863] hover:text-[#14231C] hover:bg-black/[0.03]'
          }`}
        >
          <Search className="w-3.5 h-3.5" />
          <span>Investigate</span>
        </button>

        <button
          onClick={() => onSelectTab('intelligence')}
          className={`flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${
            activeTab === 'intelligence'
              ? 'bg-white text-[#14231C] shadow-xs border border-[#D5DAD3]'
              : 'text-[#616863] hover:text-[#14231C] hover:bg-black/[0.03]'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Intelligence</span>
        </button>

        <button
          onClick={() => onSelectTab('certificates')}
          className={`flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${
            activeTab === 'certificates'
              ? 'bg-white text-[#14231C] shadow-xs border border-[#D5DAD3]'
              : 'text-[#616863] hover:text-[#14231C] hover:bg-black/[0.03]'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Certificates</span>
        </button>

        <button
          onClick={() => onSelectTab('reports')}
          className={`flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${
            activeTab === 'reports'
              ? 'bg-white text-[#14231C] shadow-xs border border-[#D5DAD3]'
              : 'text-[#616863] hover:text-[#14231C] hover:bg-black/[0.03]'
          }`}
        >
          <BarChart2 className="w-3.5 h-3.5" />
          <span>Reports</span>
        </button>

        <button
          onClick={() => onSelectTab('community')}
          className={`flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${
            activeTab === 'community'
              ? 'bg-white text-[#14231C] shadow-xs border border-[#D5DAD3]'
              : 'text-[#616863] hover:text-[#14231C] hover:bg-black/[0.03]'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>Community</span>
        </button>
      </nav>

      {/* Right: Actions & User Avatar */}
      <div className="relative flex items-center gap-3 z-10">
        <button 
          title="Security Notifications"
          className="relative w-8 h-8 rounded-full flex items-center justify-center text-[#555C57] hover:text-[#14231C] hover:bg-black/[0.04] transition-colors"
        >
          <Bell className="w-4 h-4" />
          {openThreatsCount > 0 && (
            <span className="absolute 1 top-1 right-1 w-2 h-2 bg-[#C93B2B] rounded-full ring-2 ring-[#F4F5F1]" />
          )}
        </button>

        <div className="w-8 h-8 rounded-full bg-[#3F4843] text-white flex items-center justify-center font-bold text-xs shadow-xs">
          A
        </div>
      </div>
    </header>
  );
};
