import React, { useState } from 'react';
import {
  Menu,
  Radio,
  FileText,
  Calendar,
  RotateCw,
  User,
  ChevronDown,
  LogOut,
  LogIn,
  Settings,
  FileCode,
} from 'lucide-react';
import { UserProfile } from '../types';

interface NavbarProps {
  onToggleSidebar: () => void;
  activeTab: string;
  setActiveTab: (tab: any) => void;
  onSearchChange?: (val: string) => void;
  timeRange: string;
  setTimeRange: (range: string) => void;
  onRefresh: () => void;
  onOpenAuth?: () => void;
  currentUser?: UserProfile | null;
  onLogout?: () => void;
  onOpenConfig?: () => void;
  onExploreAgent?: () => void;
  onGenerateReport?: () => void;
  currentModuleName?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  onToggleSidebar,
  activeTab,
  setActiveTab,
  onSearchChange,
  timeRange,
  setTimeRange,
  onRefresh,
  onOpenAuth,
  currentUser,
  onLogout,
  onOpenConfig,
  onExploreAgent,
  onGenerateReport,
  currentModuleName = 'Incident Response',
}) => {
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showTimeDropdown, setShowTimeDropdown] = useState(false);
  const [searchVal, setSearchVal] = useState('');

  const timeOptions = [
    { label: 'Last 15 minutes', val: '15m' },
    { label: 'Last 1 hour', val: '1h' },
    { label: 'Last 24 hours', val: '24h' },
    { label: 'Last 7 days', val: '7d' },
    { label: 'Last 30 days', val: '30d' },
  ];

  const currentOption = timeOptions.find((t) => t.val === timeRange) || timeOptions[2];

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSearchChange) onSearchChange(searchVal);
  };

  return (
    <div className="bg-white border-b border-slate-200 sticky top-0 z-40 select-none font-sans">
      {/* Row 1: Top Brand & Header Bar (Matching Image 1) */}
      <header className="h-12 px-4 flex items-center justify-between border-b border-slate-100">
        {/* Left: Hamburger + W. Logo + Incident Response Slanted Pill */}
        <div className="flex items-center gap-3">
          {/* Hamburger Menu Toggle */}
          <button
            onClick={onToggleSidebar}
            className="p-1 rounded text-slate-700 hover:bg-slate-100 hover:text-slate-900 transition-colors"
            title="Toggle Navigation Menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Wazuh Style Brand Logo: W. (or ARKA) */}
          <div className="flex items-center gap-1.5 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <span className="font-extrabold text-xl tracking-tight text-slate-900 font-sans">
              W<span className="text-[#0060df]">.</span>
            </span>
          </div>

          {/* Authentic Slanted Blue Pill: Incident Response */}
          <div className="wazuh-pill px-4 py-1 ml-1.5 shadow-sm">
            <span className="wazuh-pill-content text-xs font-bold text-[#0060df]">
              {currentModuleName}
            </span>
          </div>
        </div>

        {/* Right: Cluster Health + Tenant/User Profile */}
        <div className="flex items-center gap-4 text-xs">
          {/* Cluster Status Ring Indicator */}
          <div className="flex items-center gap-1 text-slate-500 hover:text-slate-800 cursor-pointer" title="Cluster Status: Healthy">
            <div className="w-4 h-4 rounded-full border-2 border-slate-400 flex items-center justify-center">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            </div>
          </div>

          {/* User / Tenant Dropdown */}
          <div className="relative">
            {currentUser ? (
              <button
                onClick={() => setShowProfileMenu(!showProfileMenu)}
                className="flex items-center gap-1.5 text-slate-700 hover:text-slate-900 font-medium py-1 px-2 rounded hover:bg-slate-50"
              >
                <div className="w-5 h-5 rounded-full bg-slate-200 flex items-center justify-center text-slate-600">
                  <User className="w-3.5 h-3.5" />
                </div>
                <span className="text-xs font-semibold">{currentUser.tenant_id || 'wazuh'}</span>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>
            ) : (
              <button
                onClick={onOpenAuth}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-[#0060df] hover:bg-blue-50 rounded border border-blue-200"
              >
                <LogIn className="w-3 h-3" /> Sign in
              </button>
            )}

            {/* Profile Dropdown Menu */}
            {showProfileMenu && currentUser && (
              <div className="absolute right-0 mt-2 w-56 bg-white border border-slate-200 rounded-lg shadow-xl p-3 z-50 text-slate-700">
                <div className="border-b border-slate-100 pb-2 mb-2">
                  <p className="font-bold text-xs text-slate-900">{currentUser.full_name}</p>
                  <p className="text-[11px] text-slate-500 truncate">{currentUser.email}</p>
                  <span className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] bg-blue-50 text-[#0060df] font-semibold">
                    {currentUser.role}
                  </span>
                </div>
                <div className="space-y-1 text-xs">
                  <button
                    onClick={() => {
                      setShowProfileMenu(false);
                      if (onOpenConfig) onOpenConfig();
                    }}
                    className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-slate-100 text-left"
                  >
                    <Settings className="w-3.5 h-3.5 text-slate-500" /> SIEM Configuration
                  </button>
                  <button
                    onClick={() => {
                      setShowProfileMenu(false);
                      if (onLogout) onLogout();
                    }}
                    className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-rose-50 text-rose-600 text-left"
                  >
                    <LogOut className="w-3.5 h-3.5" /> Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Row 2: Sub-navigation Tabs + Action Buttons (Matching Image 1) */}
      <div className="h-10 px-4 flex items-center justify-between text-xs font-medium">
        {/* Left Tabs */}
        <div className="flex items-center gap-6 h-full">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`h-full flex items-center px-1 border-b-2 transition-all ${
              activeTab === 'dashboard'
                ? 'border-[#0060df] text-[#0060df] font-bold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('explorer')}
            className={`h-full flex items-center px-1 border-b-2 transition-all ${
              activeTab === 'explorer'
                ? 'border-[#0060df] text-[#0060df] font-bold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Events
          </button>
          <button
            onClick={() => setActiveTab('agents')}
            className={`h-full flex items-center px-1 border-b-2 transition-all ${
              activeTab === 'agents'
                ? 'border-[#0060df] text-[#0060df] font-bold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Agents
          </button>
          <button
            onClick={() => setActiveTab('vulnerabilities')}
            className={`h-full flex items-center px-1 border-b-2 transition-all ${
              activeTab === 'vulnerabilities'
                ? 'border-[#0060df] text-[#0060df] font-bold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Vulnerabilities
          </button>
          <button
            onClick={() => setActiveTab('sca')}
            className={`h-full flex items-center px-1 border-b-2 transition-all ${
              activeTab === 'sca'
                ? 'border-[#0060df] text-[#0060df] font-bold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            SCA Compliance
          </button>
        </div>

        {/* Right Actions: ((•)) Explore agent | 📄 Generate report */}
        <div className="flex items-center gap-5 text-slate-600">
          <button
            onClick={onExploreAgent || (() => setActiveTab('agents'))}
            className="flex items-center gap-1.5 hover:text-[#0060df] transition-colors"
          >
            <Radio className="w-3.5 h-3.5 text-[#0060df]" />
            <span className="font-semibold text-slate-700 hover:text-[#0060df]">Explore agent</span>
          </button>

          <button
            onClick={onGenerateReport || (() => setActiveTab('reports'))}
            className="flex items-center gap-1.5 hover:text-[#0060df] transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-[#0060df]" />
            <span className="font-semibold text-slate-700 hover:text-[#0060df]">Generate report</span>
          </button>
        </div>
      </div>

      {/* Row 3: Search, Time Picker & Refresh Ribbon (Matching Image 1) */}
      <div className="px-4 py-2 bg-[#f8fafc] border-t border-slate-200 flex flex-col md:flex-row items-stretch md:items-center gap-2">
        {/* KQL Search Bar */}
        <form onSubmit={handleSearchSubmit} className="flex-1 flex items-center bg-white border border-slate-300 rounded shadow-sm text-xs focus-within:border-[#0060df]">
          <div className="pl-2.5 pr-1.5 text-slate-400 flex items-center">
            <FileCode className="w-3.5 h-3.5" />
            <ChevronDown className="w-3 h-3 ml-0.5" />
          </div>
          <input
            type="text"
            value={searchVal}
            onChange={(e) => setSearchVal(e.target.value)}
            placeholder="Search"
            className="flex-1 py-1.5 px-2 bg-transparent text-slate-800 placeholder:text-slate-400 focus:outline-none text-xs"
          />
          <div className="pr-2.5">
            <span className="px-1.5 py-0.5 text-[10px] font-bold bg-slate-100 text-slate-500 rounded border border-slate-200">
              KQL
            </span>
          </div>
        </form>

        {/* Time Range Selector */}
        <div className="relative">
          <button
            onClick={() => setShowTimeDropdown(!showTimeDropdown)}
            className="flex items-center justify-between gap-3 bg-white border border-slate-300 rounded px-3 py-1.5 text-xs text-slate-700 shadow-sm hover:border-slate-400"
          >
            <div className="flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-[#0060df]" />
              <span className="font-medium">{currentOption.label}</span>
            </div>
            <span className="text-[#0060df] hover:underline text-[11px] font-medium">Show dates</span>
          </button>

          {showTimeDropdown && (
            <div className="absolute right-0 mt-1 w-44 bg-white border border-slate-200 rounded-lg shadow-xl py-1 z-50 text-xs">
              {timeOptions.map((opt) => (
                <button
                  key={opt.val}
                  onClick={() => {
                    setTimeRange(opt.val);
                    setShowTimeDropdown(false);
                  }}
                  className={`w-full text-left px-3 py-1.5 hover:bg-slate-100 ${
                    timeRange === opt.val ? 'text-[#0060df] font-bold bg-blue-50' : 'text-slate-700'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 rounded text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50 hover:text-slate-900 transition-all"
        >
          <RotateCw className="w-3.5 h-3.5 text-[#0060df]" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Row 4: Filter Chips Bar (cluster.name: wazuh, rule.groups: audit, + Add filter) */}
      <div className="px-4 py-1.5 bg-[#f8fafc] border-t border-slate-200/60 flex items-center gap-2 flex-wrap text-xs">
        <div className="flex items-center gap-1.5 px-2 py-0.5 bg-white border border-slate-300 rounded text-[11px] text-slate-600 shadow-xs">
          <span>cluster.name: arka</span>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-0.5 bg-white border border-slate-300 rounded text-[11px] text-slate-600 shadow-xs">
          <span>rule.groups: audit</span>
        </div>
        <button
          onClick={() => {}}
          className="text-[#0060df] text-[11px] font-medium hover:underline flex items-center gap-1 px-1"
        >
          + Add filter
        </button>
      </div>
    </div>
  );
};
