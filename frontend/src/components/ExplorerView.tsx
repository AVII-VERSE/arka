import React, { useState } from 'react';
import { Search, RefreshCw, Terminal, Eye, FileJson } from 'lucide-react';
import { SecurityEvent } from '../types';

interface ExplorerViewProps {
  events: SecurityEvent[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const ExplorerView: React.FC<ExplorerViewProps> = ({ events, isLoading, onRefresh }) => {
  const [query, setQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const filteredEvents = events.filter((e) => {
    const matchQuery =
      query === '' ||
      e.host.toLowerCase().includes(query.toLowerCase()) ||
      e.event_type.toLowerCase().includes(query.toLowerCase()) ||
      e.action.toLowerCase().includes(query.toLowerCase()) ||
      (e.source_ip && e.source_ip.includes(query)) ||
      (e.user && e.user.toLowerCase().includes(query.toLowerCase()));

    const matchSeverity = selectedSeverity === 'ALL' || e.severity === selectedSeverity;
    return matchQuery && matchSeverity;
  });

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header & KQL Search Bar */}
      <div className="glass-card rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" /> Security Telemetry Event Explorer
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Query raw normalized logs ingested from Windows EventLogs, Linux Syslogs, and Endpoint Daemons.
            </p>
          </div>
          <button
            onClick={onRefresh}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-200 rounded-xl text-xs font-mono transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
            <span>Refresh Stream</span>
          </button>
        </div>

        {/* Lucene Query Input */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Execute Lucene query e.g. host:DC01 AND action:logon_failed OR ip:192.168.1.105..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all"
            />
          </div>
          {/* Facet Severity Filter Pills */}
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
      </div>

      {/* Main Table & Inspector Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Data Table */}
        <div className={`glass-card rounded-2xl p-5 ${selectedEvent ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-3">
            <span className="text-xs font-mono text-slate-400 font-bold">
              MATCHED LOG RECORD COUNT: <span className="text-cyan-400">{filteredEvents.length}</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Normalized ECS Schema</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-slate-300">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Host</th>
                  <th className="p-3">Event Type</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">User / IP</th>
                  <th className="p-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredEvents.map((evt) => (
                  <tr key={evt.event_id} className="hover:bg-slate-900/80 transition-colors">
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          evt.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                          evt.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          evt.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-emerald-500/20 text-emerald-400'
                        }`}
                      >
                        {evt.severity}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                    <td className="p-3 font-semibold text-slate-200">{evt.host}</td>
                    <td className="p-3 text-cyan-400">{evt.event_type}</td>
                    <td className="p-3 text-slate-300">{evt.action}</td>
                    <td className="p-3 text-slate-400">
                      {evt.user ? <span className="text-amber-300 font-bold">{evt.user}</span> : evt.source_ip || 'System'}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="px-2.5 py-1 bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-200 rounded-lg text-[11px] font-mono transition-all flex items-center gap-1 ml-auto"
                      >
                        <Eye className="w-3 h-3 text-cyan-400" /> Details
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500">
                      No security events matched current filter query.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* JSON Inspector Drawer */}
        {selectedEvent && (
          <div className="glass-card rounded-2xl p-5 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="font-bold text-slate-200 uppercase flex items-center gap-2">
                <FileJson className="w-4 h-4 text-cyan-400" /> Raw Log Record Payload
              </h4>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-500 hover:text-slate-300 text-xs">
                Close
              </button>
            </div>

            <div className="space-y-3">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1.5">
                <p className="text-[10px] text-slate-500 uppercase">Event Identifier</p>
                <p className="text-cyan-400 font-bold text-[11px] truncate">{selectedEvent.event_id}</p>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl overflow-x-auto">
                <p className="text-[10px] text-slate-500 uppercase mb-2">Normalized JSON Payload</p>
                <pre className="text-[10px] text-emerald-400 font-mono leading-relaxed">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
