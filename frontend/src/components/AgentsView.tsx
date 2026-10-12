import React, { useState } from 'react';
import { Server, Plus, Laptop, Activity } from 'lucide-react';
import { Agent } from '../types';
import { EnrollAgentModal } from './EnrollAgentModal';

interface AgentsViewProps {
  agents: Agent[];
  onRefresh?: () => void;
  onAgentAdded?: (agent: Agent) => void;
}

export const AgentsView: React.FC<AgentsViewProps> = ({ agents: initialAgents, onRefresh, onAgentAdded }) => {
  const [agents, setAgents] = useState<Agent[]>(initialAgents);
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ONLINE' | 'OFFLINE'>('ALL');

  // Keep local state in sync if prop changes
  React.useEffect(() => {
    setAgents(initialAgents);
  }, [initialAgents]);

  const handleAgentEnrolled = (newAgent: Agent) => {
    setAgents((prev) => [newAgent, ...prev]);
    if (onAgentAdded) onAgentAdded(newAgent);
    if (onRefresh) onRefresh();
  };

  const filteredAgents = agents.filter((a) => {
    if (statusFilter === 'ONLINE') return a.status === 'ONLINE';
    if (statusFilter === 'OFFLINE') return a.status !== 'ONLINE';
    return true;
  });

  const onlineCount = agents.filter((a) => a.status === 'ONLINE').length;
  const offlineCount = agents.filter((a) => a.status !== 'ONLINE').length;

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" /> ARKA Endpoint Agent Fleet Management
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Registered Windows, Linux & macOS daemons providing FIM, SCA, Syscollector & telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-xl p-1 text-xs font-mono">
            {(['ALL', 'ONLINE', 'OFFLINE'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 rounded-lg transition-all ${
                  statusFilter === st
                    ? 'bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          <button
            onClick={() => setShowEnrollModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 rounded-xl text-xs font-mono font-bold transition-all shadow-lg shadow-emerald-500/20"
          >
            <Plus className="w-4 h-4" /> Enroll New Agent
          </button>
        </div>
      </div>

      {/* Fleet KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div className="p-4 rounded-xl glass-card flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">Total Endpoints</span>
            <p className="text-2xl font-bold text-slate-100 mt-1">{agents.length}</p>
          </div>
          <Laptop className="w-6 h-6 text-cyan-400" />
        </div>
        <div className="p-4 rounded-xl glass-card flex items-center justify-between border-l-4 border-l-emerald-500">
          <div>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">Online & Healthy</span>
            <p className="text-2xl font-bold text-emerald-400 mt-1">{onlineCount}</p>
          </div>
          <Activity className="w-6 h-6 text-emerald-400 animate-pulse" />
        </div>
        <div className="p-4 rounded-xl glass-card flex items-center justify-between border-l-4 border-l-rose-500">
          <div>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">Disconnected / Offline</span>
            <p className="text-2xl font-bold text-rose-400 mt-1">{offlineCount}</p>
          </div>
          <Server className="w-6 h-6 text-rose-400" />
        </div>
      </div>

      {/* Agents Fleet Table */}
      <div className="glass-card rounded-2xl p-5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Status</th>
                <th className="p-3">Agent ID</th>
                <th className="p-3">Hostname</th>
                <th className="p-3">IP Address</th>
                <th className="p-3">OS Platform</th>
                <th className="p-3">Version</th>
                <th className="p-3">Last Heartbeat</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filteredAgents.map((agent) => (
                <tr key={agent.id} className="hover:bg-slate-900/80 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                        agent.status === 'ONLINE'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {agent.status}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-cyan-400">{agent.id}</td>
                  <td className="p-3 font-bold text-slate-100">{agent.hostname}</td>
                  <td className="p-3 text-cyan-300">{agent.ip_address}</td>
                  <td className="p-3 text-slate-300">
                    {agent.os_type} {agent.os_version ? `(${agent.os_version})` : ''}
                  </td>
                  <td className="p-3 text-slate-400">{agent.agent_version}</td>
                  <td className="p-3 text-slate-400">
                    {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleTimeString() : 'Active'}
                  </td>
                </tr>
              ))}
              {filteredAgents.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No endpoint agents currently registered under this filter. Click "Enroll New Agent" above to deploy.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enroll Modal */}
      <EnrollAgentModal
        isOpen={showEnrollModal}
        onClose={() => setShowEnrollModal(false)}
        onAgentEnrolled={handleAgentEnrolled}
      />
    </div>
  );
};
