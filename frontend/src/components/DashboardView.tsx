import React, { useState } from 'react';
import {
  ChevronRight,
  ChevronDown,
  Maximize2,
  List,
  Copy,
  Check,
  Zap,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { DashboardSummary } from '../types';
import { api } from '../api/client';

interface DashboardViewProps {
  summary?: DashboardSummary;
  isLoading: boolean;
  onNavigateTab?: (tab: any) => void;
  onRefresh?: () => void;
}

interface WazuhEventRow {
  id: string;
  timestamp: string;
  agent_name: string;
  agent_id: string;
  agent_ip: string;
  rule_groups: string;
  rule_description: string;
  rule_level: number;
  rule_id: string;
  mitre_id?: string;
  raw_log?: string;
  full_document?: Record<string, any>;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  summary: _apiSummary,
  isLoading: _isLoading,
  onNavigateTab: _onNavigateTab,
  onRefresh,
}) => {
  const [expandedRowId, setExpandedRowId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  // Wazuh Donut Chart Data (Matching Image 1: Alert groups)
  const alertGroupsData = [
    { name: 'Connection blocked', value: 52, color: '#0060df' },
    { name: 'Process stopped', value: 33, color: '#f5a623' },
    { name: 'File quarantined', value: 6, color: '#d9381e' },
    { name: 'Application removed', value: 5, color: '#80389b' },
    { name: 'Ticket opened', value: 4, color: '#00a2b0' },
  ];

  // Wazuh Bar Chart Histogram Data (Matching Image 1: Events 5,327 hits)
  const eventsHistogramData = [
    { date: '2026-05-24', count: 180 },
    { date: '2026-05-27', count: 155 },
    { date: '2026-05-31', count: 120 },
    { date: '2026-06-03', count: 210 },
    { date: '2026-06-07', count: 480 },
    { date: '2026-06-10', count: 190 },
    { date: '2026-06-14', count: 130 },
    { date: '2026-06-17', count: 270 },
    { date: '2026-06-21', count: 320 },
    { date: '2026-06-24', count: 260 },
    { date: '2026-06-28', count: 350 },
    { date: '2026-07-01', count: 200 },
    { date: '2026-07-05', count: 65 },
    { date: '2026-07-08', count: 255 },
    { date: '2026-07-12', count: 310 },
    { date: '2026-07-15', count: 195 },
    { date: '2026-07-19', count: 380 },
    { date: '2026-07-22', count: 315 },
    { date: '2026-07-26', count: 70 },
  ];

  // Wazuh Authentic Events Table Rows (Matching Image 1)
  const eventsRows: WazuhEventRow[] = [
    {
      id: 'evt-001',
      timestamp: 'Aug 16, 2026 @ 22:39:18.199',
      agent_name: 'RHEL7',
      agent_id: '001',
      agent_ip: '192.168.1.105',
      rule_groups: 'Connection blocked',
      rule_description: 'Poor reputation IP address 196.52.43.89 blocked by firewall',
      rule_level: 9,
      rule_id: '100100',
      mitre_id: 'T1071.001',
      raw_log: 'iptables: DROP IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=196.52.43.89 DST=192.168.1.105 PROTO=TCP SPT=44124 DPT=445',
    },
    {
      id: 'evt-002',
      timestamp: 'Aug 15, 2026 @ 16:29:31.754',
      agent_name: 'Windows',
      agent_id: '002',
      agent_ip: '10.0.0.12',
      rule_groups: 'File quarantined',
      rule_description: 'File C:\\Users\\Administrator\\Finance.doc quarantined',
      rule_level: 10,
      rule_id: '100125',
      mitre_id: 'T1204.002',
      raw_log: 'active-response: quarantined file C:\\Users\\Administrator\\Finance.doc (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)',
    },
    {
      id: 'evt-003',
      timestamp: 'Aug 15, 2026 @ 01:20:38.187',
      agent_name: 'Debian',
      agent_id: '003',
      agent_ip: '192.168.1.140',
      rule_groups: 'Process stopped',
      rule_description: 'Compromised process /usr/sbin/httpd stopped',
      rule_level: 12,
      rule_id: '100232',
      mitre_id: 'T1059.004',
      raw_log: 'active-response: killed PID 9812 process /usr/sbin/httpd spawned by www-data',
    },
    {
      id: 'evt-004',
      timestamp: 'Aug 14, 2026 @ 03:10:14.366',
      agent_name: 'Centos',
      agent_id: '004',
      agent_ip: '192.168.1.112',
      rule_groups: 'Application removed',
      rule_description: 'Blacklisted RPM nmap-ncat-6.40-19 removed',
      rule_level: 12,
      rule_id: '100206',
      mitre_id: 'T1078',
      raw_log: 'yum: Erased: nmap-ncat-6.40-19.el7.x86_64 policy violation trigger',
    },
    {
      id: 'evt-005',
      timestamp: 'Aug 13, 2026 @ 19:44:02.812',
      agent_name: 'Ubuntu22',
      agent_id: '005',
      agent_ip: '192.168.1.198',
      rule_groups: 'Ticket opened',
      rule_description: 'Automated SOC incident IR-2026-904 dispatched to Jira',
      rule_level: 7,
      rule_id: '100050',
      mitre_id: 'T1110',
      raw_log: 'jira-webhook: created issue SEC-4892 Severity=High Host=Ubuntu22',
    },
  ];

  const handleCopyJson = (evt: WazuhEventRow) => {
    navigator.clipboard.writeText(JSON.stringify(evt, null, 2));
    setCopiedId(evt.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleInjectSimulatedAttack = async () => {
    setSimulating(true);
    try {
      await api.simulateAttackEvent('BRUTE_FORCE');
      setToast('Simulated attack event injected into ARKA telemetry pipeline!');
      if (onRefresh) onRefresh();
      setTimeout(() => setToast(null), 4000);
    } catch (e: any) {
      setToast(`Simulation: ${e.message}`);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="p-4 space-y-4 bg-[#f5f7fa] min-h-screen font-sans select-none">
      {/* Toast Alert */}
      {toast && (
        <div className="p-2.5 rounded bg-blue-50 border border-blue-200 text-[#0060df] text-xs font-medium flex items-center justify-between">
          <span>{toast}</span>
          <button onClick={() => setToast(null)} className="text-slate-400 hover:text-slate-700">✕</button>
        </div>
      )}

      {/* Row 1: The Two Wazuh Visualization Cards (Matching Image 1) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card 1: Alert groups (Donut Chart) */}
        <div className="wazuh-card p-4 flex flex-col justify-between">
          {/* Card Header */}
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-xs text-slate-800 tracking-tight">Alert groups</span>
            <button className="text-slate-400 hover:text-slate-600 p-0.5" title="Maximize">
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Donut Chart and Legend */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-3">
            {/* Donut Graphic */}
            <div className="w-56 h-56 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={alertGroupsData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={2}
                    dataKey="value"
                    stroke="#ffffff"
                    strokeWidth={2}
                  >
                    {alertGroupsData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      border: '1px solid #cbd5e1',
                      borderRadius: '4px',
                      fontSize: '11px',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.08)',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Legend List (Matching Image 1 exactly) */}
            <div className="space-y-2 text-xs flex-1 pr-4">
              {alertGroupsData.map((item) => (
                <div key={item.name} className="flex items-center gap-2.5">
                  <span
                    className="w-3 h-3 rounded-full flex-shrink-0"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-700 text-xs font-medium">{item.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom Left Toolbar Icon */}
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <button className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100" title="View Table">
              <List className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] text-slate-400">Total Groups: 5</span>
          </div>
        </div>

        {/* Card 2: Events (Bar Chart Histogram) */}
        <div className="wazuh-card p-4 flex flex-col justify-between">
          {/* Card Header */}
          <div className="flex items-center justify-between mb-1">
            <span className="font-bold text-xs text-slate-800 tracking-tight">Events</span>
            <button className="text-slate-400 hover:text-slate-600 p-0.5" title="Maximize">
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Centered Hits Subtitle (Matching Image 1) */}
          <div className="text-center py-1">
            <p className="text-xs font-bold text-slate-700">5,327 hits</p>
            <p className="text-[10px] text-slate-400 font-mono">
              May 19, 2026 @ 10:13:25.490 - Aug 17, 2026 @ 10:13:25.490
            </p>
          </div>

          {/* Histogram Bar Chart */}
          <div className="h-52 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={eventsHistogramData} margin={{ top: 10, right: 10, left: -20, bottom: 15 }}>
                <XAxis
                  dataKey="date"
                  stroke="#94a3b8"
                  fontSize={9}
                  tickLine={false}
                  label={{ value: 'timestamp per day', position: 'insideBottom', offset: -10, fontSize: 10, fill: '#64748b' }}
                />
                <YAxis
                  stroke="#94a3b8"
                  fontSize={9}
                  tickLine={false}
                  ticks={[0, 250, 500]}
                  label={{ value: 'Count', angle: -90, position: 'insideLeft', offset: 25, fontSize: 10, fill: '#64748b' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #cbd5e1',
                    borderRadius: '4px',
                    fontSize: '11px',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.08)',
                  }}
                />
                <Bar dataKey="count" fill="#0060df" radius={[0, 0, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Bottom Left Toolbar Icon */}
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <button className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100" title="View Table">
              <List className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleInjectSimulatedAttack}
              disabled={simulating}
              className="text-[10px] text-[#0060df] hover:underline flex items-center gap-1 font-medium"
            >
              <Zap className="w-3 h-3" /> Test Telemetry Ingestion
            </button>
          </div>
        </div>
      </div>

      {/* Row 2: Full-width Events Table (Matching Image 1) */}
      <div className="wazuh-card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            {/* Table Header Columns (Matching Image 1 exactly) */}
            <thead className="bg-[#f8fafc] text-slate-600 font-semibold border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">
                  Time <span className="text-[#0060df]">▼</span>
                </th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">agent.name</th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">rule.groups</th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">rule.description</th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">rule.level</th>
                <th className="py-2.5 px-3 font-semibold text-slate-700">rule.id</th>
              </tr>
            </thead>

            {/* Table Rows (Matching Image 1 styling) */}
            <tbody className="divide-y divide-slate-100 bg-white">
              {eventsRows.map((row) => {
                const isExpanded = expandedRowId === row.id;
                return (
                  <React.Fragment key={row.id}>
                    <tr
                      onClick={() => setExpandedRowId(isExpanded ? null : row.id)}
                      className="hover:bg-blue-50/40 cursor-pointer transition-colors text-slate-700"
                    >
                      {/* Accordion Arrow Icon > */}
                      <td className="py-3 px-3 text-slate-400">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-[#0060df]" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                        )}
                      </td>

                      {/* Time */}
                      <td className="py-3 px-3 text-slate-600 whitespace-nowrap">
                        {row.timestamp}
                      </td>

                      {/* agent.name (Blue link like Image 1) */}
                      <td className="py-3 px-3 text-[#0060df] font-semibold hover:underline">
                        {row.agent_name}
                      </td>

                      {/* rule.groups */}
                      <td className="py-3 px-3 text-slate-700 font-medium">
                        {row.rule_groups}
                      </td>

                      {/* rule.description */}
                      <td className="py-3 px-3 text-slate-600 max-w-md truncate font-sans">
                        {row.rule_description}
                      </td>

                      {/* rule.level */}
                      <td className="py-3 px-3 text-slate-700 font-bold">
                        {row.rule_level}
                      </td>

                      {/* rule.id (Blue bold monospace link like Image 1) */}
                      <td className="py-3 px-3 text-[#0060df] font-bold hover:underline">
                        {row.rule_id}
                      </td>
                    </tr>

                    {/* Expandable Details Pane (Wazuh Document Inspector) */}
                    {isExpanded && (
                      <tr className="bg-slate-50 border-b border-slate-200">
                        <td colSpan={7} className="p-4">
                          <div className="bg-white border border-slate-200 rounded p-4 text-xs font-mono space-y-3">
                            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                              <span className="font-bold text-slate-800 flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-emerald-500" /> Document Details
                              </span>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCopyJson(row);
                                }}
                                className="flex items-center gap-1 px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 text-[11px]"
                              >
                                {copiedId === row.id ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                Copy JSON
                              </button>
                            </div>

                            {/* Key-Value Fields Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                              <div><span className="text-slate-400">_id:</span> <span className="text-slate-800">{row.id}</span></div>
                              <div><span className="text-slate-400">@timestamp:</span> <span className="text-slate-800">{row.timestamp}</span></div>
                              <div><span className="text-slate-400">agent.id:</span> <span className="text-slate-800">{row.agent_id}</span></div>
                              <div><span className="text-slate-400">agent.name:</span> <span className="text-[#0060df]">{row.agent_name}</span></div>
                              <div><span className="text-slate-400">agent.ip:</span> <span className="text-slate-800">{row.agent_ip}</span></div>
                              <div><span className="text-slate-400">rule.id:</span> <span className="text-[#0060df] font-bold">{row.rule_id}</span></div>
                              <div><span className="text-slate-400">rule.level:</span> <span className="text-slate-800">{row.rule_level}</span></div>
                              <div><span className="text-slate-400">rule.mitre.id:</span> <span className="text-purple-600 font-bold">{row.mitre_id}</span></div>
                            </div>

                            {/* Raw Log / Payload */}
                            {row.raw_log && (
                              <div className="pt-2 border-t border-slate-100">
                                <span className="text-slate-400 text-[10px] block mb-1">full_log:</span>
                                <pre className="p-2 bg-slate-900 text-emerald-400 rounded text-[11px] overflow-x-auto">
                                  {row.raw_log}
                                </pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
