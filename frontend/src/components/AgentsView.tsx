import React from 'react';
import { Server, Activity, Monitor, Terminal } from 'lucide-react';
import { Agent } from '../types';

interface AgentsViewProps {
  agents: Agent[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const AgentsView: React.FC<AgentsViewProps> = ({ agents, isLoading, onRefresh }) => {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Server className="w-5 h-5 text-emerald-400" /> Endpoint Agent Management
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Registered Windows & Linux endpoint daemons harvesting security telemetry.
          </p>
        </div>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Status</th>
                <th className="p-3">Hostname</th>
                <th className="p-3">IP Address</th>
                <th className="p-3">OS Platform</th>
                <th className="p-3">Agent Version</th>
                <th className="p-3">Last Heartbeat</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        agent.status === 'ONLINE'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {agent.status}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-slate-100">{agent.hostname}</td>
                  <td className="p-3 text-cyan-400">{agent.ip_address}</td>
                  <td className="p-3 text-slate-300">
                    {agent.os_type} ({agent.os_version})
                  </td>
                  <td className="p-3 text-slate-400">{agent.agent_version}</td>
                  <td className="p-3 text-slate-400">{new Date(agent.last_heartbeat).toLocaleTimeString()}</td>
                </tr>
              ))}
              {agents.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    No endpoint agents enrolled. Run `python -m arka_agent` on target host to connect.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
