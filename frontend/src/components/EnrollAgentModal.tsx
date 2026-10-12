import React, { useState } from 'react';
import { Terminal, Plus, X, Server, Copy, Check, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../api/client';
import { Agent } from '../types';

interface EnrollAgentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAgentEnrolled: (agent: Agent) => void;
}

export const EnrollAgentModal: React.FC<EnrollAgentModalProps> = ({
  isOpen,
  onClose,
  onAgentEnrolled,
}) => {
  const [tab, setTab] = useState<'ui' | 'cli'>('ui');
  const [cliOs, setCliOs] = useState<'linux' | 'windows' | 'docker'>('linux');
  
  // UI Registration state
  const [hostname, setHostname] = useState('dc-secondary-02.corp.local');
  const [ipAddress, setIpAddress] = useState('192.168.1.145');
  const [osType, setOsType] = useState('linux');
  const [osVersion, setOsVersion] = useState('Ubuntu 22.04 LTS');
  const [agentVersion, setAgentVersion] = useState('0.1.0');
  const [enrollmentToken, setEnrollmentToken] = useState('arka-default-enroll-token');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const newAgent = await api.enrollAgent({
        hostname,
        ip_address: ipAddress,
        os_type: osType,
        os_version: osVersion,
        agent_version: agentVersion,
        enrollment_token: enrollmentToken,
      });

      setSuccess(`Agent ${newAgent.hostname} successfully registered and enrolled!`);
      setTimeout(() => {
        onAgentEnrolled(newAgent);
        onClose();
      }, 700);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to enroll agent.');
    } finally {
      setLoading(false);
    }
  };

  const getCliCommand = () => {
    if (cliOs === 'windows') {
      return `powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/v1/agents/install.ps1' -OutFile 'arka_install.ps1'; .\\arka_install.ps1 -Server 'http://127.0.0.1:8000' -Token '${enrollmentToken}'"`;
    }
    if (cliOs === 'docker') {
      return `docker run -d --name arka-agent --net=host -e ARKA_SERVER=http://127.0.0.1:8000 -e ARKA_TOKEN=${enrollmentToken} avii-verse/arka-agent:latest`;
    }
    return `curl -sSL http://127.0.0.1:8000/api/v1/agents/install.sh | sudo bash -s -- --server http://127.0.0.1:8000 --token ${enrollmentToken}`;
  };

  const copyCliCommand = () => {
    navigator.clipboard.writeText(getCliCommand());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-lg p-6 overflow-hidden rounded-2xl glass-card border border-slate-700/80 shadow-2xl font-sans">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-xl bg-slate-900/80 text-slate-400 hover:text-slate-100 border border-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/5 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/20">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-mono font-bold text-slate-100 flex items-center gap-2">
              Deploy Endpoint Security Agent
            </h3>
            <p className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Fleet Registration & Real-time Telemetry Collector
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex p-1 mb-5 bg-slate-950 border border-slate-800/80 rounded-xl font-mono text-xs">
          <button
            onClick={() => setTab('ui')}
            className={`flex-1 py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-2 ${
              tab === 'ui'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Plus className="w-3.5 h-3.5" /> Instant UI Enrollment
          </button>
          <button
            onClick={() => setTab('cli')}
            className={`flex-1 py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-2 ${
              tab === 'cli'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" /> One-Line Install Script
          </button>
        </div>

        {/* Status Alerts */}
        {error && (
          <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {success && (
          <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>{success}</span>
          </div>
        )}

        {/* Tab 1: Instant UI Registration */}
        {tab === 'ui' && (
          <form onSubmit={handleEnroll} className="space-y-3 font-mono">
            <div>
              <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                Hostname
              </label>
              <input
                type="text"
                required
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="srv-prod-app01"
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  IP Address
                </label>
                <input
                  type="text"
                  required
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  placeholder="192.168.1.100"
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50"
                />
              </div>

              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  OS Platform
                </label>
                <select
                  value={osType}
                  onChange={(e) => {
                    setOsType(e.target.value);
                    if (e.target.value === 'windows') setOsVersion('Windows Server 2022');
                    else if (e.target.value === 'macos') setOsVersion('macOS Sonoma 14.5');
                    else setOsVersion('Ubuntu 22.04 LTS');
                  }}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50"
                >
                  <option value="linux">Linux (Ubuntu/Debian/RHEL)</option>
                  <option value="windows">Windows (Server/Workstation)</option>
                  <option value="macos">macOS (Darwin)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  OS Version
                </label>
                <input
                  type="text"
                  required
                  value={osVersion}
                  onChange={(e) => setOsVersion(e.target.value)}
                  placeholder="Ubuntu 22.04 LTS"
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-emerald-500/50"
                />
              </div>

              <div>
                <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Agent Version
                </label>
                <input
                  type="text"
                  required
                  value={agentVersion}
                  onChange={(e) => setAgentVersion(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-emerald-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                Enrollment Security Token
              </label>
              <input
                type="text"
                required
                value={enrollmentToken}
                onChange={(e) => setEnrollmentToken(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-emerald-400 focus:outline-none focus:border-emerald-500/50"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-3 py-2.5 px-4 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-emerald-500/20 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? 'Registering Agent...' : 'Register Endpoint Agent'}
            </button>
          </form>
        )}

        {/* Tab 2: CLI Command */}
        {tab === 'cli' && (
          <div className="space-y-4 font-mono">
            {/* Platform pills */}
            <div className="flex gap-2">
              {(['linux', 'windows', 'docker'] as const).map((os) => (
                <button
                  key={os}
                  onClick={() => setCliOs(os)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold uppercase transition-all ${
                    cliOs === os
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {os}
                </button>
              ))}
            </div>

            <p className="text-xs text-slate-400 font-sans">
              Execute this command with root / admin privileges on the target endpoint:
            </p>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl relative group">
              <code className="text-xs text-emerald-400 break-all select-all">
                {getCliCommand()}
              </code>
              <button
                onClick={copyCliCommand}
                className="absolute right-2 top-2 p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition-all"
                title="Copy Command"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
              </button>
            </div>

            <div className="pt-2 text-[11px] text-slate-500 space-y-1 font-sans">
              <p>• Automatically connects OS EventLogs (Windows 4625/4624) or Linux Syslogs.</p>
              <p>• Starts Syscollector inventory, FIM baseline, and active response agent daemon.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
