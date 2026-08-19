import React from 'react';
import {
  Activity,
  AlertTriangle,
  FileCheck,
  Server,
  KeyRound,
  ShieldAlert,
  Flame,
  Globe,
  Radio,
  ArrowUpRight,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from 'recharts';
import { DashboardSummary } from '../types';

interface DashboardViewProps {
  summary?: DashboardSummary;
  isLoading: boolean;
  onNavigateTab?: (tab: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ summary, isLoading, onNavigateTab }) => {
  if (isLoading || !summary) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono text-sm space-y-3">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p>Connecting to ARKA SIEM Processing Cluster & Ingesting Stream...</p>
      </div>
    );
  }

  const severityData = [
    { name: 'Critical', value: summary.severity_distribution.CRITICAL || 0, color: '#F43F5E' },
    { name: 'High', value: summary.severity_distribution.HIGH || 0, color: '#FB923C' },
    { name: 'Medium', value: summary.severity_distribution.MEDIUM || 0, color: '#FACC15' },
    { name: 'Low', value: summary.severity_distribution.LOW || 0, color: '#10B981' },
  ];

  // Mock Sparkline time-series stream data for event velocity
  const sparklineData = [
    { time: '10:00', events: summary.events_per_second * 0.8 },
    { time: '10:05', events: summary.events_per_second * 1.2 },
    { time: '10:10', events: summary.events_per_second * 0.9 },
    { time: '10:15', events: summary.events_per_second * 1.5 },
    { time: '10:20', events: summary.events_per_second * 1.1 },
    { time: '10:25', events: summary.events_per_second * 1.8 },
    { time: '10:30', events: summary.events_per_second },
  ];

  const mitreTacticsList = [
    { tactic: 'Initial Access', technique: 'T1190', count: summary.authentication_failures > 0 ? 4 : 0 },
    { tactic: 'Execution', technique: 'T1059.001', count: 2 },
    { tactic: 'Persistence', technique: 'T1543.003', count: 1 },
    { tactic: 'Privilege Escalation', technique: 'T1078', count: 3 },
    { tactic: 'Credential Access', technique: 'T1110', count: summary.authentication_failures },
    { tactic: 'Defense Evasion', technique: 'T1027', count: 1 },
  ];

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Top Threat Gauge & Key Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Threat Index Card */}
        <div className="glass-card rounded-2xl p-4 flex flex-col justify-between border-l-4 border-l-rose-500 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Threat Risk Gauge</span>
            <Flame className="w-4 h-4 text-rose-500 animate-pulse" />
          </div>
          <div className="my-2">
            <h3 className="text-3xl font-mono font-extrabold text-rose-500 tracking-tight">84 <span className="text-xs text-slate-400 font-normal">/ 100</span></h3>
            <p className="text-[10px] font-mono text-rose-400 font-bold uppercase mt-0.5">CRITICAL THREAT INDEX</p>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
            <div className="bg-gradient-to-r from-amber-500 to-rose-500 h-full w-[84%] rounded-full glow-rose" />
          </div>
        </div>

        {/* Event Volume & Rate */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Ingested Telemetry</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-2xl font-mono font-bold text-slate-100 tracking-tight mt-1">
              {summary.event_volume.toLocaleString()} <span className="text-xs text-slate-500 font-normal">events</span>
            </h3>
            <p className="text-[11px] font-mono text-cyan-400 font-bold mt-0.5 flex items-center gap-1">
              <Radio className="w-3 h-3 animate-pulse" /> {summary.events_per_second} events/sec
            </p>
          </div>
          <div className="h-8 -mx-2 -mb-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData}>
                <Area type="monotone" dataKey="events" stroke="#06B6D4" fill="#06B6D4" fillOpacity={0.2} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Critical / High Alerts */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 flex flex-col justify-between border-l-4 border-l-amber-500">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">High & Critical Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <h3 className="text-2xl font-mono font-bold text-amber-400 tracking-tight mt-1">
              {summary.critical_alerts + summary.high_alerts}
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              <span className="text-rose-400 font-bold">{summary.critical_alerts}</span> Critical ·{' '}
              <span className="text-amber-400 font-bold">{summary.high_alerts}</span> High
            </p>
          </div>
          <button
            onClick={() => onNavigateTab?.('alerts')}
            className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
          >
            Triage Alerts <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {/* Active Incidents */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Active Incidents</span>
            <FileCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-2xl font-mono font-bold text-slate-100 tracking-tight mt-1">
              {summary.open_incidents}
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">Multi-stage correlations</p>
          </div>
          <button
            onClick={() => onNavigateTab?.('incidents')}
            className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
          >
            Investigate Incidents <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {/* Active Agents */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 flex flex-col justify-between border-l-4 border-l-emerald-500">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Agent Fleet Status</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-2xl font-mono font-bold text-emerald-400 tracking-tight mt-1">
              {summary.active_agents} <span className="text-xs text-slate-400 font-normal">online</span>
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              {summary.offline_agents} agents disconnected
            </p>
          </div>
          <button
            onClick={() => onNavigateTab?.('agents')}
            className="text-[10px] font-mono text-emerald-400 hover:underline flex items-center gap-1 font-semibold"
          >
            Manage Agents <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Donut Chart: Alert Severity Distribution */}
        <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" /> Alert Severity Spectrum
            </h4>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Live Distribution</span>
          </div>

          <div className="h-52 relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={6}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontFamily: 'JetBrains Mono',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-mono font-extrabold text-slate-100">
                {summary.recent_alerts.length}
              </span>
              <span className="text-[9px] font-mono text-slate-400 uppercase">Total Alerts</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center justify-between p-2 rounded-xl bg-slate-900/60 border border-slate-800/60 text-xs font-mono">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-400">{item.name}</span>
                </div>
                <span className="font-bold text-slate-100">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Horizontal Bar Chart: Top Offending IPs */}
        <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" /> Top Offending Attack IPs
            </h4>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Source Ranking</span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary.top_source_ips} layout="vertical">
                <XAxis type="number" stroke="#64748B" fontSize={10} fontFamily="JetBrains Mono" />
                <YAxis dataKey="ip" type="category" stroke="#94A3B8" fontSize={10} fontFamily="JetBrains Mono" width={110} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontFamily: 'JetBrains Mono',
                  }}
                />
                <Bar dataKey="count" fill="#06B6D4" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Grid */}
        <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-400" /> MITRE ATT&CK Matrix Grid
            </h4>
            <span className="text-[10px] font-mono text-cyan-400 font-bold">TACTICS</span>
          </div>

          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {mitreTacticsList.map((item) => (
              <div
                key={item.technique}
                className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 hover:border-cyan-500/40 transition-colors"
              >
                <div>
                  <p className="text-xs font-semibold text-slate-200">{item.tactic}</p>
                  <p className="text-[10px] font-mono text-cyan-400 font-bold mt-0.5">{item.technique}</p>
                </div>
                <span
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold ${
                    item.count > 0
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 glow-rose'
                      : 'bg-slate-800 text-slate-500'
                  }`}
                >
                  {item.count} Triggers
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Real-time High & Critical Security Alerts Live Table */}
      <div className="glass-card rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-xs font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <Radio className="w-4 h-4 text-rose-500 animate-pulse" /> Live Security Alert Feed
            </h4>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Real-time deterministic detections generated across target environment.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab?.('alerts')}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-200 rounded-xl text-xs font-mono transition-all flex items-center gap-1.5"
          >
            Open Triage Workspace <ArrowUpRight className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Severity</th>
                <th className="p-3">Rule Code</th>
                <th className="p-3">Host</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Reason / Context</th>
                <th className="p-3">Status</th>
                <th className="p-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {summary.recent_alerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-900/80 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                        alert.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 glow-rose'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-cyan-400">{alert.rule_code}</td>
                  <td className="p-3 text-slate-200 font-bold">{alert.host}</td>
                  <td className="p-3 text-slate-300">{alert.source_ip || 'N/A'}</td>
                  <td className="p-3 text-slate-300 max-w-xs truncate">{alert.reason}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded-lg text-[10px] bg-slate-900 border border-slate-800 text-slate-300 font-bold">
                      {alert.status}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{new Date(alert.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {summary.recent_alerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No active security alerts recorded.
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
