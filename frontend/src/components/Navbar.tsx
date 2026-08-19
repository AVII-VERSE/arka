import React from 'react';
import { Shield, Bell, Activity, User, Search } from 'lucide-react';

interface NavbarProps {
  onSearchChange?: (val: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onSearchChange }) => {
  return (
    <header className="h-16 bg-slate-950 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="font-mono font-bold text-lg tracking-wider text-slate-100 flex items-center gap-2">
            ARKA <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-normal">v0.1.0</span>
          </div>
          <p className="text-[10px] text-slate-400 uppercase tracking-widest">Advanced Real-time Kinetic Analytics</p>
        </div>
      </div>

      <div className="flex-1 max-w-md mx-8 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Global search events, IP, user, host, rule code..."
          onChange={(e) => onSearchChange?.(e.target.value)}
          className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-colors"
        />
      </div>

      <div className="flex items-center gap-4 text-slate-300">
        <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 rounded-full">
          <Activity className="w-3.5 h-3.5 animate-pulse" />
          <span>INGESTION ACTIVE</span>
        </div>

        <button className="relative p-2 rounded-lg hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-all text-slate-400 hover:text-slate-200">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-rose-500"></span>
        </button>

        <div className="flex items-center gap-2 border-l border-slate-800 pl-4 text-xs">
          <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-mono">
            <User className="w-4 h-4" />
          </div>
          <div>
            <p className="font-semibold text-slate-200">SOC Analyst</p>
            <p className="text-[10px] text-cyan-400">CyberCorp Alpha</p>
          </div>
        </div>
      </div>
    </header>
  );
};
