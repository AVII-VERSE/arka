import React from 'react';
import {
  Activity,
  AlertTriangle,
  FileCheck,
  Server,
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
} from 'recharts';
import { DashboardSummary } from '../types';

interface DashboardViewProps {
  summary?: DashboardSummary;
  isLoading: boolean;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ summary, isLoading }) => {
  if (isLoading || !summary) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono text-sm">
        Loading real-time SOC metrics from ARKA backend...
      </div>
    );
  }

  const severityData = [
    { name: 'Critical', value: summary.severity_distribution.CRITICAL || 0, color: '#FF2A6D' },
    { name: 'High', value: summary.severity_distribution.HIGH || 0, color: '#FF9F1C' },
    { name: 'Medium', value: summary.severity_distribution.MEDIUM || 0, color: '#FFE600' },
    { name: 'Low', value: summary.severity_distribution.LOW || 0, color: '#05FFA1' },
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-mono text-slate-400 uppercase">Event Volume</p>
            <h3 className="text-2xl font-mono font-bold text-slate-100 mt-1">
              {summary.event_volume.toLocaleString()}
            </h3>
            <p className="text-[11px] text-cyan-400 mt-1 flex items-center gap-1">
              <Activity className="w-3 h-3" /> {summary.events_per_second} events/sec
            </p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-mono text-slate-400 uppercase">Critical / High Alerts</p>
            <h3 className="text-2xl font-mono font-bold text-rose-500 mt-1">
              {summary.critical_alerts + summary.high_alerts}
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">
              <span className="text-rose-500 font-bold">{summary.critical_alerts}</span> Critical |{' '}
              <span className="text-amber-400 font-bold">{summary.high_alerts}</span> High
            </p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-mono text-slate-400 uppercase">Active Incidents</p>
            <h3 className="text-2xl font-mono font-bold text-amber-400 mt-1">
              {summary.open_incidents}
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">Requiring analyst investigation</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <FileCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-[11px] font-mono text-slate-400 uppercase">Active Agents</p>
            <h3 className="text-2xl font-mono font-bold text-emerald-400 mt-1">
              {summary.active_agents}
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">
              {summary.offline_agents} agents offline
            </p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5">
          <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mb-4">
            Alert Severity Breakdown
          </h4>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={5}
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
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name}:</span>
                <span className="font-mono text-slate-200 font-bold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Source IPs */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5">
          <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mb-4">
            Top Offending Source IPs
          </h4>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary.top_source_ips} layout="vertical">
                <XAxis type="number" stroke="#64748B" fontSize={10} />
                <YAxis dataKey="ip" type="category" stroke="#64748B" fontSize={10} width={100} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" fill="#00F0FF" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE ATT&CK Breakdown */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5">
          <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mb-4">
            MITRE ATT&CK Detection Matrix
          </h4>
          <div className="space-y-3 max-h-56 overflow-y-auto pr-1">
            {summary.mitre_techniques.map((item) => (
              <div
                key={item.technique_id}
                className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800"
              >
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-mono text-[10px] border border-cyan-500/30">
                    {item.technique_id}
                  </span>
                </div>
                <span className="font-mono text-xs text-slate-200 font-bold">
                  {item.count} detections
                </span>
              </div>
            ))}
            {summary.mitre_techniques.length === 0 && (
              <div className="text-center text-xs text-slate-500 py-8">
                No active technique triggers
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5">
        <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mb-4">
          Real-time High & Critical Security Alerts
        </h4>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Severity</th>
                <th className="p-3">Rule Code</th>
                <th className="p-3">Host</th>
                <th className="p-3">Reason</th>
                <th className="p-3">Status</th>
                <th className="p-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {summary.recent_alerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        alert.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-cyan-400">{alert.rule_code}</td>
                  <td className="p-3 text-slate-200">{alert.host}</td>
                  <td className="p-3 text-slate-300">{alert.reason}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                      {alert.status}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{new Date(alert.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {summary.recent_alerts.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-slate-500">
                    No recent security alerts recorded.
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
