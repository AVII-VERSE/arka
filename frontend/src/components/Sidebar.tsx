import React from 'react';
import {
  LayoutDashboard,
  Search,
  AlertTriangle,
  FileSpreadsheet,
  Server,
  ShieldCheck,
  Settings,
  Cpu,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'explorer' | 'alerts' | 'incidents' | 'agents' | 'rules';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  alertCount: number;
  incidentCount: number;
  agentCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  alertCount,
  incidentCount,
  agentCount,
}) => {
  const operationsMenu = [
    { id: 'dashboard', label: 'SOC Executive Overview', icon: LayoutDashboard, badge: null },
    { id: 'explorer', label: 'Security Event Explorer', icon: Search, badge: 'KQL' },
    { id: 'alerts', label: 'Alert Triage Center', icon: AlertTriangle, badge: alertCount },
    { id: 'incidents', label: 'Incident Workspace', icon: FileSpreadsheet, badge: incidentCount },
  ];

  const infrastructureMenu = [
    { id: 'agents', label: 'Endpoint Agent Fleet', icon: Server, badge: agentCount },
    { id: 'rules', label: 'Detection Rules & MITRE', icon: ShieldCheck, badge: '5 Rules' },
  ];

  return (
    <aside className="w-64 bg-slate-950/90 border-r border-slate-800/80 flex flex-col justify-between p-4 sticky top-16 h-[calc(100vh-4rem)] font-mono">
      <div className="space-y-6">
        {/* Operations Section */}
        <div>
          <div className="px-3 py-1 text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">
            SOC Operations
          </div>
          <div className="space-y-1">
            {operationsMenu.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as NavTab)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-cyan-500/5 text-cyan-300 font-bold border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                      : 'text-slate-400 hover:bg-slate-900/80 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold ${
                      isActive ? 'bg-cyan-500/30 text-cyan-200' : 'bg-slate-900 text-slate-400 border border-slate-800'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Fleet & Detections Section */}
        <div>
          <div className="px-3 py-1 text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">
            Telemetry & Intelligence
          </div>
          <div className="space-y-1">
            {infrastructureMenu.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as NavTab)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-cyan-500/5 text-cyan-300 font-bold border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                      : 'text-slate-400 hover:bg-slate-900/80 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold ${
                    isActive ? 'bg-cyan-500/30 text-cyan-200' : 'bg-slate-900 text-slate-400 border border-slate-800'
                  }`}>
                    {item.badge}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* System Health Card */}
      <div className="space-y-3">
        <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Pipeline Engine
            </span>
            <span className="text-emerald-400 font-bold">HEALTHY</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full w-[85%] rounded-full animate-pulse" />
          </div>
        </div>

        <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-slate-800/60 transition-all">
          <Settings className="w-4 h-4 text-slate-500" />
          <span>SIEM Configuration</span>
        </button>
      </div>
    </aside>
  );
};
