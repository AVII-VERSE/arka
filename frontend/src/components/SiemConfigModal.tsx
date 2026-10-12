import React, { useState } from 'react';
import {
  Settings,
  X,
  Cpu,
  Database,
  Radio,
  Key,
  Shield,
  Zap,
  CheckCircle2,
  Flame,
  Terminal,
} from 'lucide-react';
import { api } from '../api/client';

interface SiemConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulateSuccess?: () => void;
}

export const SiemConfigModal: React.FC<SiemConfigModalProps> = ({
  isOpen,
  onClose,
  onSimulateSuccess,
}) => {
  const [simulating, setSimulating] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSimulate = async (type: 'BRUTE_FORCE' | 'POWERSHELL_OBFUSCATION' | 'PRIVILEGE_ESCALATION') => {
    setSimulating(type);
    setStatusMessage(null);
    try {
      await api.simulateAttackEvent(type);
      setStatusMessage(`Successfully injected ${type} security telemetry into pipeline!`);
      if (onSimulateSuccess) onSimulateSuccess();
    } catch (err: any) {
      setStatusMessage(`Simulation error: ${err.message || 'Check backend connection'}`);
    } finally {
      setSimulating(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-2xl p-6 overflow-hidden rounded-2xl glass-card border border-slate-700/80 shadow-2xl font-sans max-h-[90vh] overflow-y-auto">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-xl bg-slate-900/80 text-slate-400 hover:text-slate-100 border border-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/20">
            <Settings className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-mono font-bold text-slate-100 flex items-center gap-2">
              ARKA SIEM Core Configuration
            </h3>
            <p className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Cluster Architecture, Telemetry Pipelines & Ingestion Engine
            </p>
          </div>
        </div>

        {/* Status Message */}
        {statusMessage && (
          <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-cyan-400" />
            <span>{statusMessage}</span>
          </div>
        )}

        {/* Architecture & Cluster Health Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6 font-mono">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" /> Apache Kafka Bus
              </span>
              <span className="text-emerald-400 font-bold text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded-md border border-emerald-500/20">
                ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-slate-300 font-bold">Topic: arka.events.raw</p>
            <p className="text-[10px] text-slate-500">Consumer Group: arka-processor-group (0 drop DLQ)</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-cyan-400" /> OpenSearch Indexer
              </span>
              <span className="text-emerald-400 font-bold text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded-md border border-emerald-500/20">
                READY
              </span>
            </div>
            <p className="text-[11px] text-slate-300 font-bold">Index: arka-events-default-tenant</p>
            <p className="text-[10px] text-slate-500">Shards: 2 Primary · 1 Replica · Time-series routing</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Detection Engine
              </span>
              <span className="text-emerald-400 font-bold text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded-md border border-emerald-500/20">
                ENABLED
              </span>
            </div>
            <p className="text-[11px] text-slate-300 font-bold">YAML Rules & ASQL Evaluator</p>
            <p className="text-[10px] text-slate-500">Deterministic window correlation: 60s sliding frame</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-cyan-400" /> Agent Enrollment Token
              </span>
              <span className="text-cyan-400 font-bold text-[10px] bg-cyan-500/10 px-2 py-0.5 rounded-md border border-cyan-500/20">
                VALID
              </span>
            </div>
            <p className="text-[11px] text-emerald-400 font-bold truncate">arka-default-enroll-token</p>
            <p className="text-[10px] text-slate-500">Mutual TLS & SHA-256 token validation</p>
          </div>
        </div>

        {/* Live Attack Telemetry Injector */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" /> Interactive Telemetry & Attack Simulator
            </h4>
            <span className="text-[10px] text-slate-500 uppercase">Live Pipeline Test</span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans">
            Inject realistic enterprise attack telemetry to verify rules, alert triggers, and real-time dashboard telemetry without needing external agents:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
            <button
              onClick={() => handleSimulate('BRUTE_FORCE')}
              disabled={simulating !== null}
              className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-amber-500/40 text-left transition-all group disabled:opacity-50"
            >
              <div className="flex items-center justify-between text-xs font-bold text-amber-400 mb-1">
                <span>SSH / RDP Brute-Force</span>
                <Flame className="w-3.5 h-3.5 group-hover:animate-bounce" />
              </div>
              <p className="text-[10px] text-slate-400 font-sans">T1110 Credential Guessing</p>
            </button>

            <button
              onClick={() => handleSimulate('POWERSHELL_OBFUSCATION')}
              disabled={simulating !== null}
              className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-rose-500/40 text-left transition-all group disabled:opacity-50"
            >
              <div className="flex items-center justify-between text-xs font-bold text-rose-400 mb-1">
                <span>PowerShell Obfuscation</span>
                <Terminal className="w-3.5 h-3.5 group-hover:animate-bounce" />
              </div>
              <p className="text-[10px] text-slate-400 font-sans">T1059.001 Base64 Encoded Exec</p>
            </button>

            <button
              onClick={() => handleSimulate('PRIVILEGE_ESCALATION')}
              disabled={simulating !== null}
              className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-left transition-all group disabled:opacity-50"
            >
              <div className="flex items-center justify-between text-xs font-bold text-cyan-400 mb-1">
                <span>Sudo Root Escape</span>
                <Shield className="w-3.5 h-3.5 group-hover:animate-bounce" />
              </div>
              <p className="text-[10px] text-slate-400 font-sans">T1078 Privilege Escalation</p>
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-6 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-xl text-xs font-mono font-bold transition-all"
          >
            Close Settings
          </button>
        </div>
      </div>
    </div>
  );
};
