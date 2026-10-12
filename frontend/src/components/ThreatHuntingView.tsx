import React, { useState, useEffect } from 'react';
import { Target, Play, CheckCircle2 } from 'lucide-react';
import { api } from '../api/client';
import { ThreatHuntingPlaybook } from '../types';

export const ThreatHuntingView: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<ThreatHuntingPlaybook[]>([]);
  const [executing, setExecuting] = useState<string | null>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<ThreatHuntingPlaybook | null>(null);
  const [executionResult, setExecutionResult] = useState<any | null>(null);

  const loadData = async () => {
    try {
      const data = await api.getThreatHuntingPlaybooks();
      if (data && data.length > 0) {
        setPlaybooks(data);
        setSelectedPlaybook(data[0]);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleExecute = async (playbookId: string) => {
    setExecuting(playbookId);
    setExecutionResult(null);
    try {
      const res = await api.executePlaybook(playbookId, 'Lead SOC Analyst');
      setExecutionResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setExecuting(null);
    }
  };

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Target className="w-4 h-4 text-cyan-400" /> MITRE ATT&CK Threat Hunting Playbooks
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Structured adversary hypothesis testing and proactive query investigation workflows.
          </p>
        </div>
        <span className="text-xs font-mono px-3 py-1 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-xl font-bold">
          {playbooks.length} Active Playbooks
        </span>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        {/* Playbooks List */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Playbook Library
          </h4>
          {playbooks.map((pb) => (
            <div
              key={pb.playbook_id}
              onClick={() => {
                setSelectedPlaybook(pb);
                setExecutionResult(null);
              }}
              className={`p-4 rounded-xl cursor-pointer transition-all border ${
                selectedPlaybook?.playbook_id === pb.playbook_id
                  ? 'bg-slate-900/90 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-bold text-slate-200">{pb.name}</span>
                <span
                  className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                    pb.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {pb.severity}
                </span>
              </div>
              <p className="text-[10px] text-cyan-400 font-bold mb-2">Tactic: {pb.mitre_tactic}</p>
              <p className="text-[11px] text-slate-400 font-sans line-clamp-2">{pb.description}</p>
            </div>
          ))}
        </div>

        {/* Selected Playbook Details & Execution */}
        <div className="lg:col-span-2 glass-card rounded-2xl p-5 space-y-4">
          {selectedPlaybook ? (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-100">{selectedPlaybook.name}</h4>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    ID: <span className="text-cyan-400 font-bold">{selectedPlaybook.playbook_id}</span> ·{' '}
                    Techniques:{' '}
                    <span className="text-slate-300">
                      {selectedPlaybook.mitre_technique_ids.join(', ')}
                    </span>
                  </p>
                </div>
                <button
                  onClick={() => handleExecute(selectedPlaybook.playbook_id)}
                  disabled={executing !== null}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 rounded-xl text-xs font-bold transition-all disabled:opacity-50 shadow-lg shadow-cyan-500/10"
                >
                  <Play className={`w-3.5 h-3.5 ${executing ? 'animate-spin' : ''}`} />
                  {executing ? 'Running Hunt...' : 'Execute Playbook'}
                </button>
              </div>

              {/* Hypothesis */}
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">
                  Threat Hypothesis
                </span>
                <p className="text-xs text-slate-300 font-sans">{selectedPlaybook.hypothesis}</p>
              </div>

              {/* Steps */}
              <div className="space-y-2">
                <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                  Investigation Queries & Actions ({selectedPlaybook.steps.length} Steps)
                </span>
                <div className="space-y-2">
                  {selectedPlaybook.steps.map((st) => (
                    <div
                      key={st.step_id}
                      className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-200">
                          Step {st.step_id}: {st.action}
                        </span>
                      </div>
                      {st.query_hint && (
                        <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-[10px] text-emerald-400">
                          <code>{st.query_hint}</code>
                        </div>
                      )}
                      {st.expected_evidence && (
                        <p className="text-[10px] text-slate-400 font-sans">
                          <strong className="text-slate-300 font-mono">Expected Evidence:</strong>{' '}
                          {st.expected_evidence}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Execution Findings Output */}
              {executionResult && (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" /> Hunt Completed — Execution ID:{' '}
                      {executionResult.execution_id}
                    </span>
                    <span className="text-[10px] text-slate-400">
                      Analyst: {executionResult.analyst}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans">
                    All {executionResult.step_results?.length || 0} investigation steps executed against OpenSearch & database telemetry store.
                  </p>
                </div>
              )}
            </>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              Select a playbook to review investigation hypotheses and run hunting queries.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
