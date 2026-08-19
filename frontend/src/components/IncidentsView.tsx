import React, { useState } from 'react';
import { FileSpreadsheet } from 'lucide-react';
import { Incident, IncidentStatus } from '../types';
import { api } from '../api/client';

interface IncidentsViewProps {
  incidents: Incident[];
  onRefresh: () => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({ incidents, onRefresh }) => {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [noteText, setNoteText] = useState('');

  const handleStatusChange = async (status: IncidentStatus) => {
    if (!selectedIncident) return;
    try {
      const updated = await api.updateIncidentStatus(selectedIncident.id, status, noteText || undefined);
      setSelectedIncident(updated);
      setNoteText('');
      onRefresh();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-amber-400" /> Multi-Stage Incident Management
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Grouped alert correlations, timeline investigation, and analyst resolution notes.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`bg-slate-950 border border-slate-800 rounded-xl p-5 ${selectedIncident ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-slate-300">
              <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Status</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Title</th>
                  <th className="p-3">Analyst</th>
                  <th className="p-3">Created</th>
                  <th className="p-3 text-right">Investigate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-bold">
                        {inc.status}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        inc.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        inc.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-slate-100">{inc.title}</td>
                    <td className="p-3 text-cyan-400">SOC Analyst</td>
                    <td className="p-3 text-slate-400">{new Date(inc.created_at).toLocaleTimeString()}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="px-3 py-1 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 rounded text-[11px] font-mono"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
                {incidents.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      No open incidents requiring analyst investigation.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Incident Investigation Timeline & Analyst Notes */}
        {selectedIncident && (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h4 className="text-xs font-bold text-slate-200 uppercase">Incident Investigation Timeline</h4>
              <button onClick={() => setSelectedIncident(null)} className="text-xs text-slate-500 hover:text-slate-300">
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <h5 className="font-bold text-slate-100 mb-1">{selectedIncident.title}</h5>
                <p className="text-slate-400">{selectedIncident.description}</p>
              </div>

              <div>
                <p className="text-[10px] text-slate-500 uppercase mb-2">Analyst Investigation Notes</p>
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {selectedIncident.notes.map((n, idx) => (
                    <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded text-[11px]">
                      <div className="flex justify-between text-[10px] text-cyan-400">
                        <span>{n.author}</span>
                      </div>
                      <p className="text-slate-300 mt-1">{n.text}</p>
                    </div>
                  ))}
                  {selectedIncident.notes.length === 0 && (
                    <p className="text-[11px] text-slate-500 italic">No analyst notes recorded yet.</p>
                  )}
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <input
                  type="text"
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  placeholder="Add investigation note or forensic artifact detail..."
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-100 focus:outline-none"
                />
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'] as IncidentStatus[]).map((st) => (
                    <button
                      key={st}
                      onClick={() => handleStatusChange(st)}
                      className={`px-2 py-1 rounded text-[10px] font-bold border transition-colors ${
                        selectedIncident.status === st
                          ? 'bg-amber-500 text-black border-amber-400'
                          : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
