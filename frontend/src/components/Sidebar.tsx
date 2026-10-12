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
  Target,
  FileText,
  Bug,
  ShieldAlert,
  Code2,
  Lock,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'explorer'
  | 'alerts'
  | 'incidents'
  | 'agents'
  | 'rules'
  | 'sca'
  | 'vulnerabilities'
  | 'active_response'
  | 'playbooks'
  | 'reports'
  | 'asql';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  alertCount: number;
  incidentCount: number;
  agentCount: number;
  onOpenConfig?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  alertCount,
  incidentCount,
  agentCount,
  onOpenConfig,
}) => {
  const navSections = [
    {
      title: 'SOC Operations',
      items: [
        { id: 'dashboard' as NavTab, label: 'Security Dashboard', icon: LayoutDashboard, badge: null },
        { id: 'playbooks' as NavTab, label: 'Threat Hunting', icon: Target, badge: 'MITRE' },
        { id: 'reports' as NavTab, label: 'Executive Reports', icon: FileText, badge: 'CISO' },
      ],
    },
    {
      title: 'Detection & Triage',
      items: [
        { id: 'alerts' as NavTab, label: 'Alert Triage Center', icon: AlertTriangle, badge: alertCount },
        { id: 'incidents' as NavTab, label: 'Incident Workspace', icon: FileSpreadsheet, badge: incidentCount },
        { id: 'explorer' as NavTab, label: 'Event Explorer (KQL)', icon: Search, badge: null },
        { id: 'asql' as NavTab, label: 'ASQL Query Console', icon: Code2, badge: 'SQL' },
        { id: 'rules' as NavTab, label: 'Detection Rules & MITRE', icon: ShieldCheck, badge: null },
      ],
    },
    {
      title: 'Audit & Compliance',
      items: [
        { id: 'sca' as NavTab, label: 'CIS Hardening (SCA)', icon: Lock, badge: 'CIS' },
        { id: 'vulnerabilities' as NavTab, label: 'Vulnerability Detector', icon: Bug, badge: 'CVE' },
      ],
    },
    {
      title: 'Fleet & Response',
      items: [
        { id: 'agents' as NavTab, label: 'Endpoint Agent Fleet', icon: Server, badge: agentCount },
        { id: 'active_response' as NavTab, label: 'Active Response (EDR)', icon: ShieldAlert, badge: 'EDR' },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-slate-950/95 border-r border-slate-800/80 flex flex-col justify-between p-4 sticky top-16 h-[calc(100vh-4rem)] font-mono overflow-y-auto">
      <div className="space-y-5">
        {navSections.map((section, idx) => (
          <div key={idx}>
            <div className="px-3 py-1 text-[9px] text-slate-500 uppercase tracking-widest font-bold mb-1.5">
              {section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs transition-all ${
                      isActive
                        ? 'bg-gradient-to-r from-cyan-500/20 to-cyan-500/5 text-cyan-300 font-bold border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                        : 'text-slate-400 hover:bg-slate-900/80 hover:text-slate-200 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.badge !== null && (
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold flex-shrink-0 ${
                          isActive
                            ? 'bg-cyan-500/30 text-cyan-200'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* System Health Card & Settings */}
      <div className="space-y-2 pt-4 border-t border-slate-800/80 mt-4">
        <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5 text-[10px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Pipeline Engine
            </span>
            <span className="text-emerald-400 font-bold">HEALTHY</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full w-[92%] rounded-full animate-pulse" />
          </div>
        </div>

        <button
          onClick={onOpenConfig}
          className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium text-slate-300 hover:bg-slate-900 hover:text-cyan-300 border border-slate-800/80 transition-all group"
        >
          <div className="flex items-center gap-2.5">
            <Settings className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
            <span>SIEM Configuration</span>
          </div>
          <span className="text-[10px] text-cyan-400 font-mono">v0.1.0</span>
        </button>
      </div>
    </aside>
  );
};
