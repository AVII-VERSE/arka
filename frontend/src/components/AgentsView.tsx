import React, { useState } from 'react';
import { Server, Plus, Terminal, Copy, Check } from 'lucide-react';
import { Agent } from '../types';

interface AgentsViewProps {
  agents: Agent[];
}

export const AgentsView: React.FC<AgentsViewProps> = ({ agents }) => {
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [copied, setCopied] = useState(false);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ONLINE' | 'OFFLINE'>('ALL');

  const enrollCommand = `python -m arka_agent --server http://127.0.0.1:8000 --token dev-agent-token`;

  const copyToClipboard = () => {
    navigator.clipboard.writeText(enrollCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredAgents = agents.filter((a) => {
    if (statusFilter === 'ONLINE') return a.status === 'ONLINE';
    if (statusFilter === 'OFFLINE') return a.status !== 'ONLINE';
    return true;
  });

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" /> ARKA Endpoint Agent Fleet Management
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Registered Windows & Linux endpoint daemons harvesting real-time OS security telemetry.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-xl p-1 text-xs font-mono">
            {['ALL', 'ONLINE', 'OFFLINE'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st as any)}
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
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 rounded-xl text-xs font-mono font-bold transition-all shadow-lg shadow-cyan-500/10"
          >
            <Plus className="w-4 h-4" /> Enroll New Agent
          </button>
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
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 glow-emerald'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {agent.status}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-cyan-400">{agent.id}</td>
                  <td className="p-3 font-bold text-slate-100">{agent.hostname}</td>
                  <td className="p-3 text-cyan-400">{agent.ip_address}</td>
                  <td className="p-3 text-slate-300">
                    {agent.os_type} ({agent.os_version})
                  </td>
                  <td className="p-3 text-slate-400">{agent.agent_version}</td>
                  <td className="p-3 text-slate-400">{new Date(agent.last_heartbeat).toLocaleTimeString()}</td>
                </tr>
              ))}
              {filteredAgents.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No endpoint agents currently registered under this filter. Click "Enroll New Agent" to deploy.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enroll New Agent Modal */}
      {showEnrollModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-card max-w-lg w-full rounded-2xl p-6 space-y-4 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-sm font-bold text-slate-100 uppercase flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" /> Enroll ARKA Endpoint Agent Daemon
              </h4>
              <button onClick={() => setShowEnrollModal(false)} className="text-xs text-slate-500 hover:text-slate-300">
                Close
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Run the following CLI command on any target Windows or Linux endpoint to enroll into ARKA:
            </p>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl relative group">
              <code className="text-xs text-emerald-400 break-all">{enrollCommand}</code>
              <button
                onClick={copyToClipboard}
                className="absolute right-2 top-2 p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
              </button>
            </div>

            <div className="pt-2 text-[11px] text-slate-500 space-y-1">
              <p>• Automatically connects OS EventLogs (Windows 4625/4624) or Linux Syslogs.</p>
              <p>• Buffers events in local SQLite ring buffer if network disconnects.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
