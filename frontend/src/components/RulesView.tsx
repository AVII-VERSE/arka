import React from 'react';
import { ShieldCheck, Code, Tag } from 'lucide-react';
import { DetectionRule } from '../types';

interface RulesViewProps {
  rules: DetectionRule[];
  isLoading: boolean;
}

export const RulesView: React.FC<RulesViewProps> = ({ rules, isLoading }) => {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" /> Deterministic Detection Rule Catalog
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Active security detection rules mapped to MITRE ATT&CK tactics & techniques.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => (
          <div key={rule.id} className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-3 font-mono">
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 text-xs font-bold border border-cyan-500/20">
                {rule.rule_code}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  rule.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' :
                  rule.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' : 'bg-yellow-500/20 text-yellow-400'
                }`}
              >
                {rule.severity}
              </span>
            </div>

            <div>
              <h4 className="text-sm font-bold text-slate-100">{rule.name}</h4>
              <p className="text-xs text-slate-400 mt-1">{rule.description}</p>
            </div>

            <div className="flex items-center gap-3 pt-2 text-[11px] text-slate-400 border-t border-slate-900">
              <div className="flex items-center gap-1">
                <Tag className="w-3.5 h-3.5 text-amber-400" />
                <span>{rule.mitre_tactic}</span>
              </div>
              <div className="flex items-center gap-1 text-cyan-400 font-bold">
                <span>{rule.mitre_technique_id}</span>
              </div>
            </div>
          </div>
        ))}
        {rules.length === 0 && (
          <div className="col-span-2 p-8 text-center text-slate-500 font-mono text-xs">
            No detection rules currently loaded.
          </div>
        )}
      </div>
    </div>
  );
};
