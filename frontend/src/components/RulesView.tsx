import React, { useState } from 'react';
import { ShieldCheck, Tag, Code, CheckCircle2, XCircle } from 'lucide-react';
import { DetectionRule } from '../types';

interface RulesViewProps {
  rules: DetectionRule[];
}

export const RulesView: React.FC<RulesViewProps> = ({ rules: initialRules }) => {
  const [rules, setRules] = useState<DetectionRule[]>(initialRules);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const toggleRuleEnabled = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const filteredRules = rules.filter(
    (r) => selectedSeverity === 'ALL' || r.severity === selectedSeverity
  );

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" /> Deterministic Detection Rule Catalog
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Active threat detection rules mapped to MITRE ATT&CK tactics & techniques.
          </p>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-xl p-1 text-xs font-mono">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1 rounded-lg transition-all ${
                selectedSeverity === sev
                  ? 'bg-cyan-500/20 text-cyan-400 font-bold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Catalog Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredRules.map((rule) => (
          <div key={rule.id} className="glass-card rounded-2xl p-5 space-y-3 font-mono">
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 text-xs font-bold border border-cyan-500/20">
                {rule.rule_code}
              </span>
              <div className="flex items-center gap-2">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                    rule.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 glow-rose'
                      : rule.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-yellow-500/20 text-yellow-400'
                  }`}
                >
                  {rule.severity}
                </span>
                <button
                  onClick={() => toggleRuleEnabled(rule.id)}
                  className={`p-1 rounded-lg border transition-all ${
                    rule.enabled
                      ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400'
                      : 'bg-slate-900 border-slate-800 text-slate-500'
                  }`}
                >
                  {rule.enabled ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-bold text-slate-100">{rule.name}</h4>
              <p className="text-xs text-slate-400 mt-1">{rule.description}</p>
            </div>

            <div className="flex items-center gap-3 pt-2 text-[11px] text-slate-400 border-t border-slate-800/80">
              <div className="flex items-center gap-1">
                <Tag className="w-3.5 h-3.5 text-amber-400" />
                <span>{rule.mitre_tactic}</span>
              </div>
              <div className="flex items-center gap-1 text-cyan-400 font-bold">
                <Code className="w-3.5 h-3.5" />
                <span>{rule.mitre_technique_id}</span>
              </div>
            </div>
          </div>
        ))}
        {filteredRules.length === 0 && (
          <div className="col-span-2 p-8 text-center text-slate-500 font-mono text-xs">
            No detection rules found under this severity filter.
          </div>
        )}
      </div>
    </div>
  );
};
