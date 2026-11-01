// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  User,
  AlertCircle,
  ArrowRight,
  Globe,
  CheckCircle2,
  Cpu,
  Key,
  Eye,
  EyeOff,
  Activity,
  Terminal,
  Radio,
  FileCheck2,
} from 'lucide-react';
import { siemApi } from '../../api/siemApi';
import type { UserProfile } from '../../types/auth';
import { translations, type Language } from '../../i18n/translations';

interface LoginPageProps {
  onLoginSuccess: (user: UserProfile) => void;
  lang: Language;
  onLanguageChange: (lang: Language) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLoginSuccess,
  lang,
  onLanguageChange,
}) => {
  const [username, setUsername] = useState<string>('admin');
  const [password, setPassword] = useState<string>('TumAdmin2026!#');
  const [selectedRole, setSelectedRole] = useState<'admin' | 'analyst' | 'auditor'>('admin');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState<string>('');

  const t = translations[lang];

  // High-precision UTC Clock
  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      const timeStr = now.toISOString().replace('T', ' ').substring(0, 23) + ' UTC';
      setCurrentTime(timeStr);
    };
    updateClock();
    const interval = setInterval(updateClock, 100);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await siemApi.login(username, password);
      onLoginSuccess(res.user);
    } catch (err: any) {
      const msg = err.message || 'Authentication failed';
      if (msg.includes('502') || msg.includes('Failed to fetch')) {
        setError(
          lang === 'th'
            ? 'ไม่สามารถเชื่อมต่อเครื่องยนต์ TUM-OpenSIEM Core (พอร์ต 5001) ได้ กรุณารอสักครู่แล้วลองใหม่อีกครั้ง'
            : 'Unable to connect to TUM-OpenSIEM Core engine (port 5001). Please verify server is operational and retry.'
        );
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSelectRole = (role: 'admin' | 'analyst' | 'auditor') => {
    setSelectedRole(role);
    if (role === 'admin') {
      setUsername('admin');
      setPassword('TumAdmin2026!#');
    } else if (role === 'analyst') {
      setUsername('analyst');
      setPassword('TumAnalyst2026!#');
    } else {
      setUsername('auditor');
      setPassword('TumAuditor2026!#');
    }
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#030712] flex flex-col justify-between p-4 sm:p-6 lg:p-8 relative overflow-hidden select-none cyber-grid">
      {/* Dynamic Ambient Background Lights */}
      <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[150px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-sky-500/5 rounded-full blur-[180px] pointer-events-none" />

      {/* Background Radar Rings */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[900px] h-[900px] border border-cyan-500/5 rounded-full pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] border border-indigo-500/5 rounded-full pointer-events-none" />

      {/* TOP MILITARY HUD BAR */}
      <header className="relative z-20 flex flex-wrap items-center justify-between gap-4 max-w-7xl mx-auto w-full pb-4 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-4 h-4 animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-emerald-400 animate-beacon" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-black tracking-widest text-cyan-400 font-mono">DEFCON 2</span>
              <span className="text-[10px] text-slate-500">•</span>
              <span className="text-xs font-semibold text-slate-300 font-mono">AIR-GAPPED SOVEREIGN MESH</span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono">TUM TRUST SECURITY // MIL-STD-810H</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Live UTC Clock */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-white/10 text-slate-300 font-mono text-xs font-tabular">
            <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>{currentTime || 'SYNCHRONIZING NTP...'}</span>
          </div>

          {/* Bilingual Language Switcher */}
          <div className="flex items-center gap-1.5 bg-slate-900/90 border border-cyan-500/30 p-1 rounded-xl backdrop-blur-md shadow-lg shadow-cyan-950/40">
            <Globe className="w-3.5 h-3.5 text-cyan-400 ml-1.5 mr-0.5" />
            <button
              type="button"
              onClick={() => onLanguageChange('th')}
              className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                lang === 'th'
                  ? 'bg-gradient-to-r from-cyan-500 to-sky-500 text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>🇹🇭</span>
              <span>ไทย</span>
            </button>
            <button
              type="button"
              onClick={() => onLanguageChange('en')}
              className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                lang === 'en'
                  ? 'bg-gradient-to-r from-cyan-500 to-sky-500 text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>🇺🇸</span>
              <span>EN</span>
            </button>
          </div>
        </div>
      </header>

      {/* MAIN COMMAND AUTHENTICATION DECK */}
      <div className="my-auto py-8 relative z-10 flex items-center justify-center">
        <div className="w-full max-w-xl bg-[#080d1a]/90 border border-white/10 rounded-3xl p-6 sm:p-8 backdrop-blur-2xl shadow-2xl relative hud-box scanline-effect">
          
          {/* Top Brand Holographic Emblem */}
          <div className="flex flex-col items-center text-center pb-6 border-b border-white/10 mb-6">
            <div className="relative mb-4">
              {/* Outer rotating energy ring */}
              <div className="absolute -inset-2 rounded-2xl bg-gradient-to-tr from-cyan-500 via-indigo-500 to-cyan-400 opacity-30 blur-sm animate-pulse" />
              <div className="relative w-16 h-16 rounded-2xl bg-[#0d1527] border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_35px_rgba(56,189,248,0.35)]">
                <Shield className="w-9 h-9 text-cyan-400" />
              </div>
            </div>

            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white flex items-center gap-2">
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-sky-200 to-indigo-400">
                {t.brandName}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                v2.0 PROD
              </span>
            </h1>

            <p className="text-xs text-cyan-400 font-mono uppercase tracking-widest mt-1 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400 inline" />
              {t.loginPortalTitle}
            </p>
            <p className="text-xs text-slate-400 font-sans mt-1.5 max-w-md">
              {t.loginPortalDesc}
            </p>
          </div>

          {/* Error Notification Diagnostic */}
          {error && (
            <div className="mb-6 p-4 rounded-2xl bg-rose-950/60 border border-rose-500/40 text-rose-200 text-xs font-mono flex items-start gap-3 shadow-lg shadow-rose-950/50">
              <AlertCircle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
              <div className="flex-1">
                <span className="font-bold block text-rose-300">SECURITY GATEWAY ALERT</span>
                <span className="text-[11px] leading-relaxed text-rose-200/90">{error}</span>
              </div>
            </div>
          )}

          {/* QUICK DEMO ROLE CLEARANCE BADGES (Interactive Smart Cards) */}
          <div className="mb-6">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-cyan-400" />
                {t.quickDemoLogin}
              </span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                1-CLICK CLEARANCE
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {/* Badge 1: SecOps Director */}
              <button
                type="button"
                onClick={() => handleSelectRole('admin')}
                className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden group ${
                  selectedRole === 'admin'
                    ? 'bg-gradient-to-b from-cyan-950/70 to-slate-900 border-cyan-400 shadow-[0_0_20px_rgba(56,189,248,0.25)]'
                    : 'bg-slate-900/60 border-white/10 hover:border-white/20 hover:bg-slate-900/90'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-sm">
                    🛡️
                  </div>
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      selectedRole === 'admin'
                        ? 'bg-cyan-400 text-slate-950'
                        : 'bg-white/5 text-slate-400'
                    }`}
                  >
                    LEVEL 5
                  </span>
                </div>
                <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                  {lang === 'th' ? 'SecOps ผู้นำ' : 'SecOps Dir'}
                </div>
                <div className="text-[10px] text-cyan-400 font-mono mt-0.5">admin</div>
              </button>

              {/* Badge 2: Threat Analyst */}
              <button
                type="button"
                onClick={() => handleSelectRole('analyst')}
                className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden group ${
                  selectedRole === 'analyst'
                    ? 'bg-gradient-to-b from-indigo-950/70 to-slate-900 border-indigo-400 shadow-[0_0_20px_rgba(99,102,241,0.25)]'
                    : 'bg-slate-900/60 border-white/10 hover:border-white/20 hover:bg-slate-900/90'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-7 h-7 rounded-lg bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-sm">
                    🔍
                  </div>
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      selectedRole === 'analyst'
                        ? 'bg-indigo-400 text-slate-950'
                        : 'bg-white/5 text-slate-400'
                    }`}
                  >
                    TS // SCI
                  </span>
                </div>
                <div className="text-xs font-bold text-white group-hover:text-indigo-300 transition-colors">
                  {lang === 'th' ? 'นักวิเคราะห์ภัย' : 'Analyst'}
                </div>
                <div className="text-[10px] text-indigo-400 font-mono mt-0.5">analyst</div>
              </button>

              {/* Badge 3: Compliance Auditor */}
              <button
                type="button"
                onClick={() => handleSelectRole('auditor')}
                className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden group ${
                  selectedRole === 'auditor'
                    ? 'bg-gradient-to-b from-emerald-950/70 to-slate-900 border-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.25)]'
                    : 'bg-slate-900/60 border-white/10 hover:border-white/20 hover:bg-slate-900/90'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-7 h-7 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-sm">
                    ⚖️
                  </div>
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      selectedRole === 'auditor'
                        ? 'bg-emerald-400 text-slate-950'
                        : 'bg-white/5 text-slate-400'
                    }`}
                  >
                    SEC 26
                  </span>
                </div>
                <div className="text-xs font-bold text-white group-hover:text-emerald-300 transition-colors">
                  {lang === 'th' ? 'ผู้ตรวจ ม.26' : 'Auditor'}
                </div>
                <div className="text-[10px] text-emerald-400 font-mono mt-0.5">auditor</div>
              </button>
            </div>
          </div>

          {/* FORM CREDENTIAL INPUTS */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 font-sans">
                  <User className="w-3.5 h-3.5 text-cyan-400" />
                  {t.lblUsername}
                </label>
                <span className="text-[10px] text-slate-500 font-mono">[AUTH_IDENTITY]</span>
              </div>
              <div className="relative">
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full px-4 py-3 bg-[#0d1424] border border-white/10 focus:border-cyan-400 rounded-xl text-white font-mono text-sm focus:outline-none focus:ring-1 focus:ring-cyan-400 transition-all placeholder:text-slate-600"
                  placeholder="admin / analyst / auditor"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 font-sans">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" />
                  {t.lblPassword}
                </label>
                <span className="text-[10px] text-slate-500 font-mono">[CRYPTO_CIPHER]</span>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full pl-4 pr-11 py-3 bg-[#0d1424] border border-white/10 focus:border-cyan-400 rounded-xl text-white font-mono text-sm focus:outline-none focus:ring-1 focus:ring-cyan-400 transition-all placeholder:text-slate-600 tracking-wider"
                  placeholder="••••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 cursor-pointer p-1"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* ACTION SUBMIT BUTTON */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-3 py-3.5 px-6 rounded-2xl bg-gradient-to-r from-cyan-400 via-sky-500 to-indigo-600 hover:from-cyan-300 hover:to-indigo-500 text-slate-950 font-black text-sm uppercase tracking-wider shadow-[0_0_30px_rgba(56,189,248,0.4)] flex items-center justify-center gap-2.5 cursor-pointer transition-all active:scale-[0.98] disabled:opacity-50"
            >
              <span>{loading ? t.btnLoginning : t.btnLogin}</span>
              <ArrowRight className="w-4 h-4 stroke-[2.5]" />
            </button>
          </form>

          {/* LEGAL & CRYPTO ACCREDITATION SEALS */}
          <div className="mt-6 pt-5 border-t border-white/5 flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono text-slate-500">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>{t.complianceNote}</span>
            </div>
            <div className="flex items-center gap-2 text-slate-600">
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3 text-cyan-500" />
                FIPS-204
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <FileCheck2 className="w-3 h-3 text-indigo-500" />
                ISO 27001
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* FOOTER ACCREDITATION STRIP */}
      <footer className="relative z-20 flex flex-wrap items-center justify-between gap-2 max-w-7xl mx-auto w-full pt-4 border-t border-white/5 text-[11px] text-slate-500 font-mono">
        <div>
          <span>© 2026 TUM Trust Security Inc. All Rights Reserved.</span>
        </div>
        <div className="flex items-center gap-4 text-slate-400">
          <span className="hover:text-cyan-400 transition-colors cursor-pointer">Sovereign Air-Gap</span>
          <span>•</span>
          <span className="hover:text-cyan-400 transition-colors cursor-pointer">WORM Merkle Proof</span>
          <span>•</span>
          <span className="hover:text-cyan-400 transition-colors cursor-pointer">Thai CCA Sec. 26</span>
        </div>
      </footer>
    </div>
  );
};
