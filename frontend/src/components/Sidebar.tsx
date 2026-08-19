import React from 'react';
import {
  LayoutDashboard,
  Search,
  AlertTriangle,
  FileSpreadsheet,
  Server,
  ShieldCheck,
  Settings,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'explorer' | 'alerts' | 'incidents' | 'agents' | 'rules';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const menu = [
    { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'explorer', label: 'Event Explorer', icon: Search },
    { id: 'alerts', label: 'Alert Triage', icon: AlertTriangle },
    { id: 'incidents', label: 'Incidents', icon: FileSpreadsheet },
    { id: 'agents', label: 'Endpoint Agents', icon: Server },
    { id: 'rules', label: 'Detection Rules', icon: ShieldCheck },
  ];

  return (
    <aside className="w-60 bg-slate-950 border-r border-slate-800 flex flex-col justify-between p-4 sticky top-16 h-[calc(100vh-4rem)]">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
          Operations
        </div>
        {menu.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as NavTab)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      <div className="border-t border-slate-800 pt-4">
        <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium text-slate-400 hover:bg-slate-900 hover:text-slate-200">
          <Settings className="w-4 h-4 text-slate-500" />
          <span>Platform Settings</span>
        </button>
      </div>
    </aside>
  );
};
