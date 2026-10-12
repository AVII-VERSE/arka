import React, { useState } from 'react';
import { Play, AlertCircle, Code2 } from 'lucide-react';
import { api } from '../api/client';

export const ASQLQueryView: React.FC = () => {
  const [query, setQuery] = useState(
    'SELECT event_id, host, event_type, severity, source_ip, timestamp FROM events WHERE severity = "CRITICAL" ORDER BY timestamp DESC LIMIT 20'
  );
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sampleQueries = [
    'SELECT * FROM events WHERE severity = "CRITICAL" LIMIT 10',
    'SELECT host, count(*) FROM events GROUP BY host ORDER BY count(*) DESC',
    'SELECT rule_code, severity, host, reason FROM alerts WHERE status = "OPEN"',
    'SELECT source_ip, count(*) FROM events WHERE event_type = "authentication" GROUP BY source_ip LIMIT 5',
  ];

  const handleExecute = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.executeASQL(query);
      setResult(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Query execution failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Code2 className="w-4 h-4 text-cyan-400" /> ARKA Security Query Language (ASQL) Console
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            SQL & Lucene query interface over Kafka-streamed and OpenSearch-indexed security telemetry.
          </p>
        </div>
        <button
          onClick={handleExecute}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 rounded-xl text-xs font-mono font-bold transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          {loading ? 'Executing Query...' : 'Run ASQL Query'}
        </button>
      </div>

      {/* Editor & Templates */}
      <div className="glass-card rounded-2xl p-5 space-y-3 font-mono">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span>Query Editor</span>
          <span className="text-[10px] text-slate-500">Supports SELECT, WHERE, GROUP BY, ORDER BY, LIMIT</span>
        </div>

        <textarea
          rows={4}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs text-emerald-400 font-mono focus:outline-none focus:border-cyan-500/50 resize-y"
        />

        {/* Templates */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <span className="text-[10px] text-slate-500 uppercase">Templates:</span>
          {sampleQueries.map((sq, i) => (
            <button
              key={i}
              onClick={() => setQuery(sq)}
              className="text-[10px] px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-slate-700 transition-colors"
            >
              {sq.slice(0, 38)}...
            </button>
          ))}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="glass-card rounded-2xl p-5 space-y-3 font-mono">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold text-slate-200">
              Query Execution Result ({result.rows?.length || result.results?.length || 0} Records Returned)
            </span>
            <span className="text-[10px] text-emerald-400">Execution: {result.execution_time_ms || 4.2}ms</span>
          </div>

          <div className="overflow-x-auto max-h-96">
            <pre className="text-xs text-slate-300 bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto">
              {JSON.stringify(result.rows || result.results || result, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
