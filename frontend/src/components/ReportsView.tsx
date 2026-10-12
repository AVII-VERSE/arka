import React, { useState, useEffect } from 'react';
import { FileText, Download, Plus, Calendar } from 'lucide-react';
import { api } from '../api/client';
import { ExecutiveReport } from '../types';

export const ReportsView: React.FC = () => {
  const [reports, setReports] = useState<ExecutiveReport[]>([]);
  const [generating, setGenerating] = useState(false);
  const [selectedReport, setSelectedReport] = useState<ExecutiveReport | null>(null);

  const loadData = async () => {
    try {
      const data = await api.getReports();
      if (data && data.length > 0) {
        setReports(data);
        setSelectedReport(data[0]);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const rep = await api.generateReport(`SOC Executive Security Briefing - ${new Date().toLocaleDateString()}`);
      setReports((prev) => [rep, ...prev]);
      setSelectedReport(rep);
    } catch (e) {
      console.error(e);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = (report: ExecutiveReport) => {
    const blob = new Blob([report.html_content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ARKA_SOC_Report_${report.report_id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" /> Automated SOC Compliance & Executive Reports
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Aggregates SIEM, SCA, Vulnerabilities, and Alerts into executive briefings.
          </p>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 rounded-xl text-xs font-mono font-bold transition-all shadow-lg shadow-cyan-500/10 disabled:opacity-50"
        >
          <Plus className="w-4 h-4" />
          {generating ? 'Compiling Briefing...' : 'Generate Executive Report'}
        </button>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        {/* Reports List */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Generated Reports ({reports.length})
          </h4>
          {reports.map((rep) => (
            <div
              key={rep.report_id}
              onClick={() => setSelectedReport(rep)}
              className={`p-4 rounded-xl cursor-pointer transition-all border ${
                selectedReport?.report_id === rep.report_id
                  ? 'bg-slate-900/90 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-slate-200">{rep.title}</span>
                <span className="text-xs font-extrabold text-cyan-400">{rep.security_score}/100</span>
              </div>
              <p className="text-[10px] text-slate-400 flex items-center gap-1.5 mt-2">
                <Calendar className="w-3 h-3 text-slate-500" />{' '}
                {new Date(rep.created_at).toLocaleDateString()}
              </p>
            </div>
          ))}
        </div>

        {/* Selected Report Preview */}
        <div className="lg:col-span-2 glass-card rounded-2xl p-5 space-y-4">
          {selectedReport ? (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-100">{selectedReport.title}</h4>
                  <p className="text-[11px] text-slate-400">Tenant: {selectedReport.tenant_id}</p>
                </div>
                <button
                  onClick={() => handleDownload(selectedReport)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 rounded-xl text-xs font-bold transition-all"
                >
                  <Download className="w-3.5 h-3.5" /> Download HTML Report
                </button>
              </div>

              {/* Metrics Summary Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase">Security Score</span>
                  <p className="text-xl font-bold text-cyan-400 mt-1">{selectedReport.security_score}%</p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase">Active Endpoints</span>
                  <p className="text-xl font-bold text-emerald-400 mt-1">{selectedReport.metrics.active_agents}</p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase">CIS Pass Rate</span>
                  <p className="text-xl font-bold text-cyan-300 mt-1">{selectedReport.metrics.sca_pass_rate}%</p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase">Total Alerts</span>
                  <p className="text-xl font-bold text-amber-400 mt-1">{selectedReport.metrics.total_alerts}</p>
                </div>
              </div>

              {/* Report HTML Preview */}
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950 p-4">
                <div
                  className="text-xs text-slate-300 font-sans prose prose-invert max-w-none"
                  dangerouslySetInnerHTML={{ __html: selectedReport.html_content }}
                />
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              Select or generate a report to inspect metrics and briefings.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
