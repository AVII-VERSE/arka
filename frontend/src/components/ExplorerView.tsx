import React, { useState } from 'react';
import { Search, Filter, RefreshCw, Terminal, Eye } from 'lucide-react';
import { SecurityEvent } from '../types';

interface ExplorerViewProps {
  events: SecurityEvent[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const ExplorerView: React.FC<ExplorerViewProps> = ({ events, isLoading, onRefresh }) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const filteredEvents = events.filter((e) => {
    const matchesSearch =
      !search ||
      e.message.toLowerCase().includes(search.toLowerCase()) ||
      e.host.toLowerCase().includes(search.toLowerCase()) ||
      (e.user && e.user.toLowerCase().includes(search.toLowerCase()));

    const matchesSeverity = !severityFilter || e.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="p-6 space-y-6">
      {/* Explorer Search & Facet Control Bar */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search raw event logs by host, user, IP, process, or message..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button
            onClick={onRefresh}
            className="flex items-center gap-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 px-3 py-2 rounded-lg text-xs font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Main Events Table & Detail Drawer Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`bg-slate-950 border border-slate-800 rounded-xl p-5 ${selectedEvent ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" /> Security Event Stream ({filteredEvents.length} records)
            </h4>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-slate-300">
              <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Source Type</th>
                  <th className="p-3">Host</th>
                  <th className="p-3">User</th>
                  <th className="p-3">Action</th>
                  <th className="p-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredEvents.map((evt) => (
                  <tr key={evt.event_id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="p-3 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        evt.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' :
                        evt.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' :
                        evt.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="p-3 text-cyan-400">{evt.source_type}</td>
                    <td className="p-3 text-slate-200">{evt.host}</td>
                    <td className="p-3 text-slate-300">{evt.user || '-'}</td>
                    <td className="p-3 font-semibold text-slate-200">{evt.action}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500">
                      No security events match the active search filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Event Detail JSON Drawer */}
        {selectedEvent && (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-xs font-mono font-bold text-slate-200 uppercase">Event Raw Telemetry</h4>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                Close
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Event ID:</span>
                <span className="text-cyan-400 truncate max-w-[180px]">{selectedEvent.event_id}</span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Host:</span>
                <span className="text-slate-200">{selectedEvent.host}</span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">User:</span>
                <span className="text-slate-200">{selectedEvent.user || 'N/A'}</span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Source IP:</span>
                <span className="text-slate-200">{selectedEvent.source_ip || 'N/A'}</span>
              </div>
            </div>

            <div className="pt-2">
              <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Payload JSON</p>
              <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-80">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
