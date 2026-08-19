import React from 'react';
import {
  Shield,
  Bell,
  Activity,
  User,
  Search,
  Clock,
  ChevronDown,
  AlertOctagon,
} from 'lucide-react';

interface NavbarProps {
  onSearchChange?: (val: string) => void;
  timeRange: string;
  setTimeRange: (range: string) => void;
  criticalAlertCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  onSearchChange,
  timeRange,
  setTimeRange,
  criticalAlertCount,
}) => {
  const threatLevel = criticalAlertCount > 0 ? 'CRITICAL' : 'ELEVATED';

  return (
    <header className="h-16 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-50 shadow-2xl">
      {/* Brand & Logo */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="font-mono font-bold text-xl tracking-wider text-slate-100 flex items-center gap-2">
            ARKA <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold tracking-normal">ENTERPRISE SIEM v0.1.0</span>
          </div>
          <p className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">Advanced Real-time Kinetic Analytics</p>
        </div>
      </div>

      {/* Global Lucene / Event Search Input */}
      <div className="flex-1 max-w-xl mx-8 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Global search events: host:DC01 AND action:logon_failed OR ip:192.168.1.105..."
          onChange={(e) => onSearchChange?.(e.target.value)}
          className="w-full bg-slate-900/90 border border-slate-800 rounded-xl pl-10 pr-4 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all shadow-inner"
        />
      </div>

      {/* Right Action Bar */}
      <div className="flex items-center gap-4 text-slate-300">
        {/* Threat Level Gauge */}
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-mono font-bold ${
          threatLevel === 'CRITICAL'
            ? 'bg-rose-500/10 border-rose-500/30 text-rose-400 animate-pulse'
            : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
        }`}>
          <AlertOctagon className="w-4 h-4" />
          <span>THREAT: {threatLevel}</span>
        </div>

        {/* Time Range Selector */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs font-mono">
          <Clock className="w-3.5 h-3.5 text-slate-400 ml-2" />
          {['5m', '15m', '1h', '24h'].map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={`px-2.5 py-1 rounded-lg transition-all ${
                timeRange === r
                  ? 'bg-cyan-500/20 text-cyan-400 font-bold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {r}
            </button>
          ))}
        </div>

        {/* Live Stream Indicator */}
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-xl">
          <Activity className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
          <span className="text-[11px] font-bold">KAFKA STREAM ACTIVE</span>
        </div>

        {/* Notification Bell */}
        <button className="relative p-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 transition-all">
          <Bell className="w-4 h-4" />
          {criticalAlertCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[9px] font-bold flex items-center justify-center border-2 border-slate-950">
              {criticalAlertCount}
            </span>
          )}
        </button>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 border-l border-slate-800 pl-4 text-xs font-mono">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-slate-800 border border-cyan-500/30 flex items-center justify-center text-cyan-300 font-mono font-bold shadow-md">
            <User className="w-4 h-4" />
          </div>
          <div>
            <p className="font-bold text-slate-200 flex items-center gap-1">
              Alex Mercer <ChevronDown className="w-3 h-3 text-slate-500" />
            </p>
            <p className="text-[10px] text-cyan-400">CyberCorp Alpha (SOC Lead)</p>
          </div>
        </div>
      </div>
    </header>
  );
};
