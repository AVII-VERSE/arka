import React, { useState } from 'react';
import {
  Shield,
  Bell,
  Activity,
  User,
  Search,
  Clock,
  ChevronDown,
  AlertOctagon,
  LogOut,
  LogIn,
  Zap,
} from 'lucide-react';
import { UserProfile } from '../types';

interface NavbarProps {
  onSearchChange?: (val: string) => void;
  timeRange: string;
  setTimeRange: (range: string) => void;
  criticalAlertCount: number;
  onOpenNotifications?: () => void;
  onOpenAuth?: () => void;
  currentUser?: UserProfile | null;
  onLogout?: () => void;
  onOpenConfig?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onSearchChange,
  timeRange,
  setTimeRange,
  criticalAlertCount,
  onOpenNotifications,
  onOpenAuth,
  currentUser,
  onLogout,
  onOpenConfig,
}) => {
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  const threatLevel = criticalAlertCount > 0 ? 'CRITICAL' : 'ELEVATED';

  return (
    <header className="h-16 bg-slate-950/95 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-40 shadow-2xl">
      {/* Brand & Logo */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="font-mono font-bold text-xl tracking-wider text-slate-100 flex items-center gap-2">
            ARKA <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">SIEM & XDR</span>
          </div>
          <p className="text-[9px] text-slate-400 uppercase tracking-widest font-mono">
            Advanced Real-time Kinetic Analytics
          </p>
        </div>
      </div>

      {/* Global KQL / Event Search Input */}
      <div className="flex-1 max-w-xl mx-6 relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Global search events: host:DC01 AND action:logon_failed OR ip:192.168.1.105..."
          onChange={(e) => onSearchChange?.(e.target.value)}
          className="w-full bg-slate-900/90 border border-slate-800 rounded-xl pl-10 pr-4 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all shadow-inner"
        />
      </div>

      {/* Right Action Bar */}
      <div className="flex items-center gap-3 text-slate-300">
        {/* Threat Level Gauge */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-xl border text-[11px] font-mono font-bold ${
            threatLevel === 'CRITICAL'
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-400 animate-pulse'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
          }`}
        >
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>THREAT: {threatLevel}</span>
        </div>

        {/* Time Range Selector */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-xl p-0.5 text-xs font-mono">
          <Clock className="w-3 h-3 text-slate-400 ml-1.5" />
          {['15m', '1h', '24h', '7d'].map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={`px-2 py-0.5 rounded-lg transition-all text-[11px] ${
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
        <div className="hidden xl:flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-xl">
          <Activity className="w-3 h-3 animate-pulse text-emerald-400" />
          <span className="text-[10px] font-bold">KAFKA STREAM ACTIVE</span>
        </div>

        {/* Notification Bell */}
        <button
          onClick={onOpenNotifications}
          className="relative p-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 transition-all"
          title="Open Notifications"
        >
          <Bell className="w-4 h-4" />
          {criticalAlertCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[9px] font-bold flex items-center justify-center border-2 border-slate-950 animate-bounce">
              {criticalAlertCount}
            </span>
          )}
        </button>

        {/* User Profile / Login */}
        <div className="relative border-l border-slate-800 pl-3 text-xs font-mono">
          {currentUser ? (
            <button
              onClick={() => setShowProfileMenu(!showProfileMenu)}
              className="flex items-center gap-2 text-left hover:opacity-80 transition-opacity"
            >
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-slate-800 border border-cyan-500/30 flex items-center justify-center text-cyan-300 font-mono font-bold shadow-md">
                <User className="w-4 h-4" />
              </div>
              <div className="hidden md:block">
                <p className="font-bold text-slate-200 text-xs flex items-center gap-1">
                  {currentUser.full_name} <ChevronDown className="w-3 h-3 text-slate-500" />
                </p>
                <p className="text-[9px] text-cyan-400">
                  {currentUser.role} ({currentUser.tenant_id})
                </p>
              </div>
            </button>
          ) : (
            <button
              onClick={onOpenAuth}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 font-bold text-xs transition-all shadow-lg shadow-cyan-500/10"
            >
              <LogIn className="w-3.5 h-3.5" /> Sign In / Demo
            </button>
          )}

          {/* Profile Dropdown Modal */}
          {showProfileMenu && currentUser && (
            <div className="absolute right-0 mt-3 w-64 glass-card rounded-2xl p-4 space-y-3 z-50 shadow-2xl border border-slate-800 font-mono">
              <div className="border-b border-slate-800 pb-2">
                <p className="font-bold text-slate-100 text-xs">{currentUser.full_name}</p>
                <p className="text-[10px] text-slate-400">{currentUser.email}</p>
              </div>
              <div className="space-y-1 text-[10px] text-slate-400">
                <div className="flex items-center justify-between">
                  <span>Role:</span>
                  <span className="text-cyan-400 font-bold">{currentUser.role}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Tenant ID:</span>
                  <span className="text-slate-200 truncate max-w-[120px]">{currentUser.tenant_id}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Session:</span>
                  <span className="text-emerald-400 font-bold">Active (JWT)</span>
                </div>
              </div>
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    if (onOpenConfig) onOpenConfig();
                  }}
                  className="w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-bold transition-all"
                >
                  <Zap className="w-3.5 h-3.5 text-cyan-400" /> SIEM Configuration
                </button>
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    if (onLogout) onLogout();
                  }}
                  className="w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-rose-400 text-xs font-bold transition-all"
                >
                  <LogOut className="w-3.5 h-3.5" /> Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
