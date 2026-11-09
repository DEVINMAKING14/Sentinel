import React from 'react';
import { 
  GitFork, 
  AlertTriangle, 
  ShieldCheck, 
  Layers, 
  Radio, 
  Code2 
} from 'lucide-react';

export type SubTabType = 'lab' | 'findings' | 'certificate' | 'security' | 'threat-intel' | 'raw-data';

interface InvestigationSubTabsProps {
  activeSubTab: SubTabType;
  onSelectSubTab: (tab: SubTabType) => void;
  findingsCount: number;
}

export const InvestigationSubTabs: React.FC<InvestigationSubTabsProps> = ({
  activeSubTab,
  onSelectSubTab,
  findingsCount,
}) => {
  const tabs = [
    { id: 'lab' as const, label: 'Investigation Lab', icon: GitFork },
    { id: 'findings' as const, label: `Findings (${findingsCount})`, icon: AlertTriangle },
    { id: 'certificate' as const, label: 'Certificate', icon: ShieldCheck },
    { id: 'security' as const, label: 'Security', icon: Layers },
    { id: 'threat-intel' as const, label: 'Threat Intel', icon: Radio },
    { id: 'raw-data' as const, label: 'Raw Data', icon: Code2 },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2 mb-6">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeSubTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onSelectSubTab(tab.id)}
            className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-xl transition-all shadow-xs ${
              isActive
                ? 'bg-[#182C23] text-white shadow-sm'
                : 'bg-white hover:bg-neutral-50 text-[#555C57] border border-[#D5DAD3]'
            }`}
          >
            <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-emerald-300' : 'text-[#747C78]'}`} />
            <span>{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
};
