import React from 'react';
import {
  ShieldAlert,
  Search,
  Server,
  Lock,
  Bug,
  Target,
  FileText,
  Code2,
  Settings,
  ShieldCheck,
  X,
  FileSpreadsheet,
  AlertTriangle,
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
  isOpen: boolean;
  onClose: () => void;
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  alertCount: number;
  incidentCount: number;
  agentCount: number;
  onOpenConfig?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  isOpen,
  onClose,
  activeTab,
  setActiveTab,
  alertCount,
  incidentCount,
  agentCount,
  onOpenConfig,
}) => {
  if (!isOpen) return null;

  const menuSections = [
    {
      title: 'Endpoint Security',
      items: [
        { id: 'dashboard' as NavTab, label: 'Incident Response / Overview', icon: ShieldAlert, badge: null },
        { id: 'explorer' as NavTab, label: 'Security Events (Logs)', icon: Search, badge: null },
        { id: 'vulnerabilities' as NavTab, label: 'Vulnerabilities', icon: Bug, badge: 'CVE' },
        { id: 'sca' as NavTab, label: 'Policy Monitoring (SCA)', icon: Lock, badge: 'CIS' },
      ],
    },
    {
      title: 'Threat Intelligence',
      items: [
        { id: 'playbooks' as NavTab, label: 'Threat Hunting (MITRE)', icon: Target, badge: null },
        { id: 'rules' as NavTab, label: 'Rules & Decoders', icon: ShieldCheck, badge: null },
        { id: 'alerts' as NavTab, label: 'Alert Triage Center', icon: AlertTriangle, badge: alertCount },
        { id: 'incidents' as NavTab, label: 'Incident Workspace', icon: FileSpreadsheet, badge: incidentCount },
      ],
    },
    {
      title: 'Management',
      items: [
        { id: 'agents' as NavTab, label: 'Agents Fleet', icon: Server, badge: agentCount },
        { id: 'active_response' as NavTab, label: 'Active Response (EDR)', icon: ShieldAlert, badge: 'EDR' },
        { id: 'reports' as NavTab, label: 'Executive Reports', icon: FileText, badge: null },
        { id: 'asql' as NavTab, label: 'Dev Tools (ASQL Query)', icon: Code2, badge: 'SQL' },
      ],
    },
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs select-none font-sans">
      <div className="absolute inset-y-0 left-0 max-w-full flex">
        <aside className="w-72 bg-white border-r border-slate-200 shadow-2xl flex flex-col justify-between">
          {/* Drawer Header */}
          <div className="h-12 px-4 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#0060df] flex items-center justify-center text-white font-black text-xs font-mono shadow-xs">
                A
              </div>
              <span className="font-extrabold text-sm text-slate-900 tracking-wider font-mono">
                ARKA SIEM
              </span>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Nav Menu Content */}
          <div className="flex-1 overflow-y-auto p-3 space-y-4">
            {menuSections.map((sec, idx) => (
              <div key={idx}>
                <div className="px-3 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  {sec.title}
                </div>
                <div className="space-y-0.5 mt-1">
                  {sec.items.map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => {
                          setActiveTab(item.id);
                          onClose();
                        }}
                        className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition-all ${
                          isActive
                            ? 'bg-blue-50 text-[#0060df] font-bold border-l-4 border-[#0060df]'
                            : 'text-slate-700 hover:bg-slate-50 hover:text-slate-900 font-medium'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 truncate">
                          <Icon className={`w-4 h-4 ${isActive ? 'text-[#0060df]' : 'text-slate-500'}`} />
                          <span className="truncate">{item.label}</span>
                        </div>
                        {item.badge !== null && (
                          <span
                            className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              isActive
                                ? 'bg-blue-200 text-[#0060df]'
                                : 'bg-slate-100 text-slate-600'
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

          {/* Drawer Footer */}
          <div className="p-3 border-t border-slate-200 bg-slate-50 space-y-2">
            <button
              onClick={() => {
                onClose();
                if (onOpenConfig) onOpenConfig();
              }}
              className="w-full flex items-center justify-between px-3 py-2 rounded bg-white border border-slate-200 hover:border-slate-300 text-xs text-slate-700 font-medium transition-all"
            >
              <div className="flex items-center gap-2">
                <Settings className="w-4 h-4 text-slate-500" />
                <span>Cluster Settings</span>
              </div>
              <span className="text-[10px] text-slate-400 font-mono">v4.8</span>
            </button>
          </div>
        </aside>
      </div>
    </div>
  );
};
