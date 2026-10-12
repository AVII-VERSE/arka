import React, { useState } from 'react';
import { Shield, Lock, Mail, User, Building, ArrowRight, CheckCircle2, AlertCircle, KeyRound, Sparkles } from 'lucide-react';
import { api } from '../api/client';
import { UserProfile } from '../types';

interface LoginPageProps {
  onLoginSuccess: (user: UserProfile) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [tenantName, setTenantName] = useState('ARKA Primary SOC');
  const [tenantSlug, setTenantSlug] = useState('arka-soc');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleLogin = async (e?: React.FormEvent, customEmail?: string, customPassword?: string) => {
    if (e) e.preventDefault();
    setError(null);
    setLoading(true);

    const loginEmail = customEmail || email;
    const loginPassword = customPassword || password;

    try {
      await api.login(loginEmail, loginPassword);
      // Fetch authenticated user profile
      const user = await api.getMe();
      onLoginSuccess(user);
    } catch (err: any) {
      console.error('Login failure:', err);
      setError(
        err.response?.data?.detail ||
        'Authentication failed. Please verify your credentials or server connection.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAdminLogin = () => {
    setEmail('admin@arka-siem.org');
    setPassword('admin123');
    handleLogin(undefined, 'admin@arka-siem.org', 'admin123');
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      // 1. Create or ensure tenant
      let currentTenantId = 'default-tenant';
      try {
        const tenantRes = await api.registerTenant(tenantName, tenantSlug);
        if (tenantRes?.id) currentTenantId = tenantRes.id;
      } catch (tErr: any) {
        // If tenant already exists, proceed to user registration
      }

      // 2. Register user
      await api.registerUser({
        email,
        password,
        full_name: fullName,
        tenant_id: currentTenantId,
        role: 'SECURITY_ANALYST',
      });

      setSuccessMsg('Account registered successfully! Logging you in...');
      setTimeout(() => {
        handleLogin(undefined, email, password);
      }, 1000);
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.response?.data?.detail || 'Registration failed. Check details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0c1427] via-[#101b38] to-[#090e1d] flex flex-col items-center justify-center p-4 selection:bg-[#0060df] selection:text-white font-sans text-slate-100">
      {/* Background cyber ambient glow */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative z-10">
        {/* ARKA Brand Emblem & Title */}
        <div className="flex flex-col items-center mb-6">
          <div className="flex items-center space-x-3 mb-2">
            <div className="w-11 h-11 rounded-lg bg-gradient-to-br from-[#0060df] to-[#0091ff] flex items-center justify-center shadow-lg shadow-blue-500/20 ring-1 ring-white/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div className="flex flex-col">
              <span className="text-2xl font-bold tracking-wider text-white flex items-center gap-2">
                ARKA
                <span className="text-[10px] uppercase font-semibold tracking-widest bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded">
                  SIEM &bull; XDR
                </span>
              </span>
              <span className="text-xs text-slate-400 tracking-tight">
                Advanced Real-time Kinetic Analytics
              </span>
            </div>
          </div>
        </div>

        {/* Card Box */}
        <div className="bg-[#141e33]/90 backdrop-blur-xl border border-slate-700/60 rounded-xl shadow-2xl p-7 text-slate-200">
          {/* Mode Switch Tabs */}
          <div className="flex border-b border-slate-700/70 mb-6">
            <button
              type="button"
              onClick={() => { setMode('login'); setError(null); }}
              className={`flex-1 pb-3 text-sm font-semibold transition-colors border-b-2 ${
                mode === 'login'
                  ? 'border-[#0060df] text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Analyst Sign In
            </button>
            <button
              type="button"
              onClick={() => { setMode('register'); setError(null); }}
              className={`flex-1 pb-3 text-sm font-semibold transition-colors border-b-2 ${
                mode === 'register'
                  ? 'border-[#0060df] text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Register Workspace
            </button>
          </div>

          {/* Alerts */}
          {error && (
            <div className="mb-5 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="mb-5 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Login Form */}
          {mode === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@arka-siem.org"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df] focus:ring-1 focus:ring-[#0060df] transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df] focus:ring-1 focus:ring-[#0060df] transition-all"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-2.5 px-4 bg-[#0060df] hover:bg-[#0051bf] text-white rounded-lg font-semibold text-sm transition-all shadow-md shadow-blue-600/30 flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {loading ? (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <span>Authenticate & Access Console</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

              {/* 1-Click Quick Demo Login */}
              <div className="pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={handleQuickAdminLogin}
                  disabled={loading}
                  className="w-full py-2 px-3 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-600/60 rounded-lg text-xs font-medium text-slate-300 hover:text-white transition-all flex items-center justify-center gap-2 group"
                >
                  <Sparkles className="w-3.5 h-3.5 text-blue-400 group-hover:scale-110 transition-transform" />
                  <span>1-Click Sign In as Primary SOC Admin</span>
                </button>
                <p className="text-[11px] text-center text-slate-500 mt-2">
                  Default credentials: <code className="text-blue-400">admin@arka-siem.org</code> / <code className="text-blue-400">admin123</code>
                </p>
              </div>
            </form>
          ) : (
            /* Register Form */
            <form onSubmit={handleRegister} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Jane Doe"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@arka-siem.org"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Password (min 8 chars)
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Tenant Organization
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type="text"
                    required
                    value={tenantName}
                    onChange={(e) => {
                      setTenantName(e.target.value);
                      setTenantSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '-'));
                    }}
                    placeholder="SOC Operations Unit"
                    className="w-full bg-[#0c1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#0060df]"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-2.5 px-4 bg-[#0060df] hover:bg-[#0051bf] text-white rounded-lg font-semibold text-sm transition-all shadow-md shadow-blue-600/30 flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {loading ? (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <span>Create Account & Tenant</span>
                    <KeyRound className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          )}
        </div>

        {/* Footer info */}
        <div className="mt-6 text-center text-xs text-slate-500">
          <p>ARKA High-Performance Kinetic SIEM & XDR Platform</p>
          <p className="text-[11px] text-slate-600 mt-1">
            Built for enterprise threat intelligence, log analysis, and automated active response.
          </p>
        </div>
      </div>
    </div>
  );
};
