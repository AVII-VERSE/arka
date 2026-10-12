import React, { useState } from 'react';
import { Shield, KeyRound, User, Mail, Building, LogIn, UserPlus, CheckCircle2, AlertCircle, X, Sparkles } from 'lucide-react';
import { api } from '../api/client';
import { UserProfile } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserProfile) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onAuthSuccess }) => {
  const [tab, setTab] = useState<'login' | 'register'>('login');
  
  // Login State
  const [loginEmail, setLoginEmail] = useState('analyst@mysoc.com');
  const [loginPassword, setLoginPassword] = useState('SecurePass123!');
  
  // Register State
  const [regFullName, setRegFullName] = useState('Senior SOC Analyst');
  const [regEmail, setRegEmail] = useState('analyst@mysoc.com');
  const [regPassword, setRegPassword] = useState('SecurePass123!');
  const [regTenantName, setRegTenantName] = useState('Enterprise SOC');
  const [regRole, setRegRole] = useState('SECURITY_ANALYST');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLogin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await api.login(loginEmail, loginPassword);
      const user = await api.getMe();
      setSuccessMsg('Authenticated successfully!');
      setTimeout(() => {
        onAuthSuccess(user);
        onClose();
      }, 500);
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Login failed. Please check credentials.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      // 1. Register Tenant
      const slug = regTenantName.toLowerCase().replace(/[^a-z0-9]/g, '-');
      const tenant = await api.registerTenant(regTenantName, slug);
      
      // 2. Register User
      await api.registerUser({
        email: regEmail,
        password: regPassword,
        full_name: regFullName,
        tenant_id: tenant.id,
        role: regRole,
      });

      // 3. Login
      await api.login(regEmail, regPassword);
      const user = await api.getMe();
      setSuccessMsg('Tenant & Analyst account created successfully!');
      setTimeout(() => {
        onAuthSuccess(user);
        onClose();
      }, 700);
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Registration failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = () => {
    // Instant SOC analyst session with default tenant
    const demoUser: UserProfile = {
      id: 'usr-analyst-01',
      email: 'analyst@arka-siem.org',
      full_name: 'Lead SOC Analyst',
      tenant_id: 'default-tenant',
      role: 'SECURITY_ANALYST',
      is_active: true,
    };
    localStorage.setItem('arka_token', 'dev-demo-jwt-token');
    setSuccessMsg('Demo Analyst session initialized!');
    setTimeout(() => {
      onAuthSuccess(demoUser);
      onClose();
    }, 400);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-md p-6 overflow-hidden rounded-2xl glass-card border border-slate-700/80 shadow-2xl font-sans">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-xl bg-slate-900/80 text-slate-400 hover:text-slate-100 border border-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-mono font-bold text-slate-100 flex items-center gap-2">
              ARKA Access Portal
            </h3>
            <p className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Enterprise SIEM & SOC Authentication
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex p-1 mb-5 bg-slate-950 border border-slate-800/80 rounded-xl font-mono text-xs">
          <button
            onClick={() => { setTab('login'); setError(null); setSuccessMsg(null); }}
            className={`flex-1 py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-2 ${
              tab === 'login'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LogIn className="w-3.5 h-3.5" /> Sign In
          </button>
          <button
            onClick={() => { setTab('register'); setError(null); setSuccessMsg(null); }}
            className={`flex-1 py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-2 ${
              tab === 'register'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <UserPlus className="w-3.5 h-3.5" /> Create Tenant & Account
          </button>
        </div>

        {/* Error / Success Alerts */}
        {error && (
          <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {successMsg && (
          <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Tab 1: Sign In */}
        {tab === 'login' && (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Analyst Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="analyst@mysoc.com"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Password
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs rounded-xl shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? 'Authenticating...' : 'Sign In to SIEM'}
            </button>

            <div className="pt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={handleDemoLogin}
                className="w-full py-2 px-3 bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 text-cyan-300 font-mono text-xs rounded-xl transition-all flex items-center justify-center gap-2"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                Quick 1-Click SOC Demo Login
              </button>
            </div>
          </form>
        )}

        {/* Tab 2: Register Tenant & User */}
        {tab === 'register' && (
          <form onSubmit={handleRegister} className="space-y-3">
            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Organization / Tenant Name
              </label>
              <div className="relative">
                <Building className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  value={regTenantName}
                  onChange={(e) => setRegTenantName(e.target.value)}
                  placeholder="Global SOC Corp"
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  value={regFullName}
                  onChange={(e) => setRegFullName(e.target.value)}
                  placeholder="Jane Security"
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Work Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="analyst@corp.com"
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Password (min 8 chars)
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  minLength={8}
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                SOC Role
              </label>
              <select
                value={regRole}
                onChange={(e) => setRegRole(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                <option value="SECURITY_ANALYST">Security Analyst (Triage & Response)</option>
                <option value="SOC_MANAGER">SOC Manager (Incident Lead)</option>
                <option value="ADMIN">System Administrator</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-mono font-bold text-xs rounded-xl shadow-lg shadow-emerald-500/20 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? 'Creating Tenant...' : 'Initialize Tenant & Access'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
