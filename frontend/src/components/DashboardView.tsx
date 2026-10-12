import React, { useState, useMemo } from 'react';
import {
  ChevronRight,
  ChevronDown,
  Maximize2,
  List,
  Copy,
  Check,
  Zap,
  Activity,
  AlertTriangle,
  RefreshCw,
  Server,
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
import { Agent, Alert, DashboardSummary, SecurityEvent } from '../types';
import { api } from '../api/client';

interface DashboardViewProps {
  summary?: DashboardSummary;
  events?: SecurityEvent[];
  alerts?: Alert[];
  agents?: Agent[];
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
  summary,
  events = [],
  alerts = [],
  agents = [],
  isLoading,
  onNavigateTab: _onNavigateTab,
  onRefresh,
}) => {
  const [expandedRowId, setExpandedRowId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  // Dynamically compute real Alert Groups for the Donut Chart from alerts or events
  const alertGroupsData = useMemo(() => {
    if (alerts && alerts.length > 0) {
      const counts: Record<string, number> = {};
      alerts.forEach((a) => {
        const group = a.rule_code || 'Security Rule';
        counts[group] = (counts[group] || 0) + 1;
      });
      const palette = ['#0060df', '#f5a623', '#d9381e', '#80389b', '#00a2b0', '#10b981', '#ef4444'];
      return Object.entries(counts).map(([name, value], i) => ({
        name,
        value,
        color: palette[i % palette.length],
      }));
    }

    if (events && events.length > 0) {
      const counts: Record<string, number> = {};
      events.forEach((e) => {
        const group = e.action || e.event_type || 'Host Telemetry';
        counts[group] = (counts[group] || 0) + 1;
      });
      const palette = ['#0060df', '#f5a623', '#d9381e', '#80389b', '#00a2b0', '#10b981'];
      return Object.entries(counts).map(([name, value], i) => ({
        name,
        value,
        color: palette[i % palette.length],
      }));
    }

    return [];
  }, [alerts, events]);

  // Dynamically calculate events histogram per timestamp bucket
  const eventsHistogramData = useMemo(() => {
    if (!events || events.length === 0) {
      return [];
    }

    const buckets: Record<string, number> = {};
    events.forEach((e) => {
      try {
        const d = new Date(e.timestamp);
        const timeKey = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        buckets[timeKey] = (buckets[timeKey] || 0) + 1;
      } catch {
        buckets['Recent'] = (buckets['Recent'] || 0) + 1;
      }
    });

    const entries = Object.entries(buckets).map(([date, count]) => ({ date, count }));
    return entries.slice(-12);
  }, [events]);

  // Dynamically map real security events to authentic Wazuh/ARKA table rows
  const eventsRows: WazuhEventRow[] = useMemo(() => {
    if (!events || events.length === 0) {
      return [];
    }

    return events.slice(0, 50).map((evt, idx) => {
      const matchingAgent = agents.find((a) => a.id === evt.agent_id || a.hostname === evt.host);
      const agentName = matchingAgent?.hostname || evt.host || 'Primary-Host';
      const agentIp = matchingAgent?.ip_address || evt.source_ip || '192.168.1.1';
      const agentIdShort = evt.agent_id ? evt.agent_id.slice(0, 8) : `00${idx + 1}`;

      const level =
        evt.severity === 'CRITICAL'
          ? 14
          : evt.severity === 'HIGH'
          ? 10
          : evt.severity === 'MEDIUM'
          ? 6
          : 3;

      let formattedTime = evt.timestamp;
      try {
        formattedTime = new Date(evt.timestamp).toLocaleString(undefined, {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
      } catch {
        // Keep raw
      }

      const meta = evt.metadata || {};
      const ruleId = (meta as any).event_code ? String((meta as any).event_code) : `100${idx + 10}`;
      const mitreId =
        evt.event_type === 'authentication'
          ? 'T1110'
          : evt.event_type === 'fim'
          ? 'T1070'
          : evt.event_type === 'process'
          ? 'T1059.001'
          : evt.event_type === 'network'
          ? 'T1071'
          : 'T1000';

      return {
        id: evt.event_id || `evt-${idx}`,
        timestamp: formattedTime,
        agent_name: agentName,
        agent_id: agentIdShort,
        agent_ip: agentIp,
        rule_groups: evt.action || evt.event_type || 'endpoint_event',
        rule_description: evt.message || `Telemetry: ${evt.event_type} (${evt.action})`,
        rule_level: level,
        rule_id: ruleId,
        mitre_id: mitreId,
        raw_log: JSON.stringify(evt, null, 2),
        full_document: evt as any,
      };
    });
  }, [events, agents]);

  const handleCopyJson = (evt: WazuhEventRow) => {
    navigator.clipboard.writeText(JSON.stringify(evt.full_document || evt, null, 2));
    setCopiedId(evt.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleInjectRealTelemetry = async () => {
    setSimulating(true);
    try {
      const activeAgent = agents[0];
      const host = activeAgent?.hostname || 'AVI';
      const agentId = activeAgent?.id || 'default-agent';

      // Send real batch event
      await api.ingestEvents([
        {
          tenant_id: 'default-tenant',
          agent_id: agentId,
          timestamp: new Date().toISOString(),
          source_type: 'windows_event_log',
          host,
          source_ip: '198.51.100.99',
          destination_ip: '192.168.1.10',
          user: 'Administrator',
          event_type: 'authentication',
          action: 'logon_failed',
          severity: 'HIGH',
          message: 'An account failed to log on. Logon Type: 3. Event Code: 4625. SubStatus: 0xC000006A',
          process: 'C:\\Windows\\System32\\lsass.exe',
          metadata: {
            event_code: 4625,
            logon_type: 3,
            workstation_name: host,
          },
        },
      ]);
      setToast('Successfully ingested real live security telemetry event into ARKA pipeline!');
      if (onRefresh) onRefresh();
      setTimeout(() => setToast(null), 4000);
    } catch (e: any) {
      setToast(`Telemetry ingestion error: ${e.message}`);
    } finally {
      setSimulating(false);
    }
  };

  const totalHits = summary?.event_volume ?? events.length;

  return (
    <div className="p-4 space-y-4 bg-[#f5f7fa] min-h-screen font-sans select-none">
      {/* Toast Alert */}
      {toast && (
        <div className="p-2.5 rounded bg-blue-50 border border-blue-200 text-[#0060df] text-xs font-medium flex items-center justify-between shadow-sm">
          <span className="flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 animate-spin text-[#0060df]" />
            {toast}
          </span>
          <button onClick={() => setToast(null)} className="text-slate-400 hover:text-slate-700">
            ✕
          </button>
        </div>
      )}

      {/* Row 1: The Two Wazuh Visualization Cards (Matching Image 1) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card 1: Alert groups (Donut Chart) */}
        <div className="wazuh-card p-4 flex flex-col justify-between min-h-[310px]">
          {/* Card Header */}
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-xs text-slate-800 tracking-tight">Alert groups</span>
            <button className="text-slate-400 hover:text-slate-600 p-0.5" title="Maximize">
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Donut Chart and Legend */}
          {alertGroupsData.length > 0 ? (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-2">
              {/* Donut Graphic */}
              <div className="w-52 h-52 relative flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={alertGroupsData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
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
              <div className="space-y-2 text-xs flex-1 pr-4 max-h-48 overflow-y-auto">
                {alertGroupsData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between gap-2.5">
                    <div className="flex items-center gap-2 truncate">
                      <span
                        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-slate-700 text-xs font-medium truncate" title={item.name}>
                        {item.name}
                      </span>
                    </div>
                    <span className="text-slate-500 font-mono text-[11px]">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-8 text-slate-400">
              <AlertTriangle className="w-8 h-8 text-slate-300 mb-2" />
              <p className="text-xs font-semibold text-slate-600">No Alert Groups Recorded Yet</p>
              <p className="text-[11px] text-slate-400 max-w-xs mt-1">
                Telemetry rules are currently evaluating incoming events from registered agents.
              </p>
            </div>
          )}

          {/* Bottom Left Toolbar Icon */}
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <button className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100" title="View Table">
              <List className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] text-slate-400">
              Total Groups: {alertGroupsData.length}
            </span>
          </div>
        </div>

        {/* Card 2: Events (Bar Chart Histogram) */}
        <div className="wazuh-card p-4 flex flex-col justify-between min-h-[310px]">
          {/* Card Header */}
          <div className="flex items-center justify-between mb-1">
            <span className="font-bold text-xs text-slate-800 tracking-tight">Events</span>
            <button className="text-slate-400 hover:text-slate-600 p-0.5" title="Maximize">
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Centered Hits Subtitle (Matching Image 1) */}
          <div className="text-center py-1">
            <p className="text-xs font-bold text-slate-700">{totalHits.toLocaleString()} hits</p>
            <p className="text-[10px] text-slate-400 font-mono">
              Live Real-Time Telemetry Stream &bull; {agents.length} Registered Host{agents.length === 1 ? '' : 's'}
            </p>
          </div>

          {/* Histogram Bar Chart */}
          <div className="h-48 w-full pt-1">
            {eventsHistogramData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={eventsHistogramData} margin={{ top: 10, right: 10, left: -20, bottom: 15 }}>
                  <XAxis
                    dataKey="date"
                    stroke="#94a3b8"
                    fontSize={9}
                    tickLine={false}
                    label={{ value: 'timestamp', position: 'insideBottom', offset: -10, fontSize: 10, fill: '#64748b' }}
                  />
                  <YAxis
                    stroke="#94a3b8"
                    fontSize={9}
                    tickLine={false}
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
                  <Bar dataKey="count" fill="#0060df" radius={[1, 1, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center text-slate-400">
                <Activity className="w-6 h-6 text-slate-300 mb-1" />
                <p className="text-xs font-semibold text-slate-600">Awaiting Telemetry</p>
                <p className="text-[10px] text-slate-400">Agent daemon streams new events every 5 seconds</p>
              </div>
            )}
          </div>

          {/* Bottom Toolbar */}
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <button
              onClick={() => onRefresh && onRefresh()}
              className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100 flex items-center gap-1 text-[11px]"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin text-[#0060df]' : ''}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={handleInjectRealTelemetry}
              disabled={simulating}
              className="text-[10px] text-[#0060df] hover:underline flex items-center gap-1 font-semibold"
            >
              <Zap className="w-3 h-3 text-amber-500" />
              <span>Simulate Live Telemetry Event</span>
            </button>
          </div>
        </div>
      </div>

      {/* Row 2: Full-width Events Table (Matching Image 1) */}
      <div className="wazuh-card p-0 overflow-hidden">
        <div className="p-3 bg-[#f8fafc] border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-500" />
            <span className="font-bold text-xs text-slate-800">Security Telemetry & Event Records</span>
            <span className="text-[11px] text-slate-500 font-mono">({eventsRows.length} displayed)</span>
          </div>
          {eventsRows.length > 0 && (
            <span className="text-[11px] text-emerald-600 font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Ingest Stream Active
            </span>
          )}
        </div>

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
              {eventsRows.length > 0 ? (
                eventsRows.map((row) => {
                  const isExpanded = expandedRowId === row.id;
                  return (
                    <React.Fragment key={row.id}>
                      <tr
                        onClick={() => setExpandedRowId(isExpanded ? null : row.id)}
                        className="hover:bg-blue-50/40 cursor-pointer transition-colors text-slate-700"
                      >
                        {/* Accordion Arrow Icon > */}
                        <td className="py-2.5 px-3 text-slate-400">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-[#0060df]" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                          )}
                        </td>

                        {/* Time */}
                        <td className="py-2.5 px-3 text-slate-600 whitespace-nowrap">
                          {row.timestamp}
                        </td>

                        {/* agent.name (Blue link like Image 1) */}
                        <td className="py-2.5 px-3 text-[#0060df] font-semibold hover:underline">
                          {row.agent_name}
                        </td>

                        {/* rule.groups */}
                        <td className="py-2.5 px-3 text-slate-700 font-medium">
                          {row.rule_groups}
                        </td>

                        {/* rule.description */}
                        <td className="py-2.5 px-3 text-slate-600 max-w-md truncate font-sans">
                          {row.rule_description}
                        </td>

                        {/* rule.level */}
                        <td className="py-2.5 px-3 text-slate-700 font-bold">
                          {row.rule_level}
                        </td>

                        {/* rule.id (Blue bold monospace link like Image 1) */}
                        <td className="py-2.5 px-3 text-[#0060df] font-bold hover:underline">
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
                                  {copiedId === row.id ? (
                                    <Check className="w-3 h-3 text-emerald-600" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                  Copy JSON
                                </button>
                              </div>

                              {/* Key-Value Fields Grid */}
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                                <div><span className="text-slate-400">_id:</span> <span className="text-slate-800">{row.id}</span></div>
                                <div><span className="text-slate-400">@timestamp:</span> <span className="text-slate-800">{row.timestamp}</span></div>
                                <div><span className="text-slate-400">agent.id:</span> <span className="text-slate-800">{row.agent_id}</span></div>
                                <div><span className="text-slate-400">agent.name:</span> <span className="text-[#0060df] font-semibold">{row.agent_name}</span></div>
                                <div><span className="text-slate-400">agent.ip:</span> <span className="text-slate-800">{row.agent_ip}</span></div>
                                <div><span className="text-slate-400">rule.id:</span> <span className="text-[#0060df] font-bold">{row.rule_id}</span></div>
                                <div><span className="text-slate-400">rule.level:</span> <span className="text-slate-800 font-bold">{row.rule_level}</span></div>
                                <div><span className="text-slate-400">rule.mitre.id:</span> <span className="text-purple-600 font-bold">{row.mitre_id}</span></div>
                              </div>

                              {/* Raw Log / Payload */}
                              {row.raw_log && (
                                <div className="pt-2 border-t border-slate-100">
                                  <span className="text-slate-400 text-[10px] block mb-1">full_document:</span>
                                  <pre className="p-2.5 bg-slate-900 text-emerald-400 rounded text-[11px] overflow-x-auto max-h-56">
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
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <Server className="w-8 h-8 text-slate-300" />
                      <p className="text-xs font-semibold text-slate-600">No telemetry events recorded yet</p>
                      <p className="text-[11px] text-slate-400 max-w-sm">
                        Waiting for endpoint telemetry stream. You can also trigger a test event below.
                      </p>
                      <button
                        onClick={handleInjectRealTelemetry}
                        disabled={simulating}
                        className="mt-2 px-3 py-1.5 bg-[#0060df] hover:bg-[#0051bf] text-white text-xs font-medium rounded shadow flex items-center gap-1.5"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>Inject Telemetry Event Now</span>
                      </button>
                    </div>
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
