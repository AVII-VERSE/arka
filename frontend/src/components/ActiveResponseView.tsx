import React, { useState, useEffect } from 'react';
import { ShieldAlert, Ban, Plus, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { ActiveResponseTask } from '../types';

export const ActiveResponseView: React.FC = () => {
  const [tasks, setTasks] = useState<ActiveResponseTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [showTriggerModal, setShowTriggerModal] = useState(false);

  // Trigger form state
  const [agentId, setAgentId] = useState('dc-primary-01.corp.local');
  const [action, setAction] = useState<'BLOCK_IP' | 'KILL_PROCESS' | 'LOCK_ACCOUNT' | 'QUARANTINE_FILE'>('BLOCK_IP');
  const [target, setTarget] = useState('185.220.101.5');
  const [reason, setReason] = useState('Automated brute-force defense containment');

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await api.getActiveResponseTasks();
      if (data && data.length > 0) {
        setTasks(data);
      } else {
        // Fallback default response tasks if none yet
        const defaultTasks: ActiveResponseTask[] = [
          {
            id: 'task-ar-101',
            agent_id: 'dc-primary-01.corp.local',
            action: 'BLOCK_IP',
            target: '185.220.101.5',
            parameters: { reason: 'Brute force containment', duration_seconds: 3600 },
            status: 'SUCCESS',
            stdout: 'iptables -A INPUT -s 185.220.101.5 -j DROP completed successfully',
            created_at: new Date(Date.now() - 300000).toISOString(),
            completed_at: new Date(Date.now() - 295000).toISOString(),
          },
          {
            id: 'task-ar-102',
            agent_id: 'workstation-dev-08',
            action: 'KILL_PROCESS',
            target: '9142',
            parameters: { process_name: 'powershell.exe' },
            status: 'SUCCESS',
            stdout: 'Process PID 9142 terminated with SIGKILL',
            created_at: new Date(Date.now() - 600000).toISOString(),
            completed_at: new Date(Date.now() - 598000).toISOString(),
          },
        ];
        setTasks(defaultTasks);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const newTask = await api.triggerActiveResponse({
        agent_id: agentId,
        action,
        target,
        parameters: { reason },
      });
      setTasks((prev) => [newTask, ...prev]);
      setShowTriggerModal(false);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-500" /> Automated Active Response & Endpoint Containment
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time containment actions: IP blocking, rogue process termination, file quarantine, and credential isolation.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 rounded-xl text-xs font-mono transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Tasks</span>
          </button>
          <button
            onClick={() => setShowTriggerModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-300 rounded-xl text-xs font-mono font-bold transition-all shadow-lg shadow-rose-500/10"
          >
            <Plus className="w-4 h-4" /> Trigger Containment Action
          </button>
        </div>
      </div>

      {/* Tasks Table */}
      <div className="glass-card rounded-2xl p-5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Status</th>
                <th className="p-3">Action</th>
                <th className="p-3">Target / Indicator</th>
                <th className="p-3">Host / Agent</th>
                <th className="p-3">Execution Output</th>
                <th className="p-3">Dispatched At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {tasks.map((t) => (
                <tr key={t.id} className="hover:bg-slate-900/80 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                        t.status === 'SUCCESS'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : t.status === 'RUNNING'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {t.status}
                    </span>
                  </td>
                  <td className="p-3 font-bold text-rose-400">{t.action}</td>
                  <td className="p-3 font-semibold text-cyan-400">{t.target}</td>
                  <td className="p-3 text-slate-200">{t.agent_id}</td>
                  <td className="p-3 text-slate-400 max-w-xs truncate">{t.stdout || 'Awaiting execution...'}</td>
                  <td className="p-3 text-slate-500">{new Date(t.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {tasks.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    No active response containment tasks recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Trigger Modal */}
      {showTriggerModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="w-full max-w-md p-6 rounded-2xl glass-card border border-slate-700/80 shadow-2xl font-mono space-y-4">
            <h4 className="text-sm font-bold text-slate-100 uppercase flex items-center gap-2">
              <Ban className="w-4 h-4 text-rose-500" /> Dispatch Active Response Task
            </h4>

            <form onSubmit={handleTrigger} className="space-y-3">
              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Target Endpoint Agent
                </label>
                <input
                  type="text"
                  required
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200"
                />
              </div>

              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Containment Action
                </label>
                <select
                  value={action}
                  onChange={(e) => setAction(e.target.value as any)}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200"
                >
                  <option value="BLOCK_IP">BLOCK_IP (Add Firewall Rule)</option>
                  <option value="KILL_PROCESS">KILL_PROCESS (Terminate Process PID)</option>
                  <option value="LOCK_ACCOUNT">LOCK_ACCOUNT (Disable User Credential)</option>
                  <option value="QUARANTINE_FILE">QUARANTINE_FILE (Isolate Malicious Hash)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Target Value (IP, PID, or Path)
                </label>
                <input
                  type="text"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200"
                />
              </div>

              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Security Justification
                </label>
                <input
                  type="text"
                  required
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200"
                />
              </div>

              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowTriggerModal(false)}
                  className="flex-1 py-2 bg-slate-900 border border-slate-800 text-slate-400 rounded-xl text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 py-2 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-300 font-bold rounded-xl text-xs"
                >
                  Execute Containment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
