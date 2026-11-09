// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  User,
  AlertCircle,
  ArrowRight,
  Search,
  Scale,
  CheckCircle2,
  Cpu,
  Key,
  Eye,
  EyeOff,
  Activity,
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
            ? 'ไม่สามารถเชื่อมต่อเครื่องยนต์ TUM-OpenSIEM Core ได้ กรุณารอสักครู่แล้วลองใหม่อีกครั้ง'
            : 'Unable to connect to TUM-OpenSIEM Core engine. Please verify server is operational and retry.'
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
    <div className="min-h-screen bg-[#0b0f14] flex flex-col justify-between p-4 sm:p-6 lg:p-8 relative select-none">
      {/* Top Bar with Sovereign Clearance Indicators */}
      <div className="flex items-center justify-between max-w-7xl mx-auto w-full">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-[#1f6feb] flex items-center justify-center text-white">
            <Shield className="w-4 h-4 fill-current" />
          </div>
          <div>
            <span className="text-xs font-bold tracking-tight text-[#f0f6fc] block">
              {t.brandName}
            </span>
            <span className="text-[10px] text-[#8b949e] font-mono tracking-wider uppercase block">
              ENTERPRISE CONSOLE
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* UTC NTP Clock */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#161b22] border border-[#21262d] text-[11px] font-mono text-[#8b949e] font-tabular">
            <Activity className="w-3 h-3 text-[#58a6ff]" />
            <span>{currentTime}</span>
          </div>

          {/* Language Switcher */}
          <div className="flex items-center bg-[#161b22] border border-[#30363d] rounded p-0.5">
            <button
              type="button"
              onClick={() => onLanguageChange('th')}
              className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
                lang === 'th' ? 'bg-[#1f6feb] text-white' : 'text-[#8b949e] hover:text-[#f0f6fc]'
              }`}
            >
              TH
            </button>
            <button
              type="button"
              onClick={() => onLanguageChange('en')}
              className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
                lang === 'en' ? 'bg-[#1f6feb] text-white' : 'text-[#8b949e] hover:text-[#f0f6fc]'
              }`}
            >
              EN
            </button>
          </div>
        </div>
      </div>

      {/* Main Login Card */}
      <div className="flex items-center justify-center my-6">
        <div className="w-full max-w-lg bg-[#161b22] border border-[#21262d] rounded p-6 sm:p-7 relative">
          {/* Card Header */}
          <div className="text-center mb-6">
            <div className="inline-flex w-12 h-12 rounded bg-[#1f6feb] items-center justify-center text-white mb-3">
              <Shield className="w-6 h-6 fill-current" />
            </div>
            <h1 className="text-lg sm:text-xl font-bold text-[#f0f6fc] tracking-tight">
              {t.loginPortalTitle}
            </h1>
            <p className="text-xs text-[#8b949e] mt-1 font-sans">
              {t.loginPortalDesc}
            </p>
          </div>

          {/* Error Message Box */}
          {error && (
            <div className="mb-4 p-3 rounded bg-[#3c1e1e] border border-[#f85149]/40 text-[#f85149] text-xs font-mono flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-[#f85149]" />
              <div className="flex-1">
                <span className="font-bold block text-[#f85149]">SECURITY GATEWAY ALERT</span>
                <span className="text-[11px] leading-relaxed text-[#f85149]/90">{error}</span>
              </div>
            </div>
          )}

          {/* Quick Demo Role Clearance Badges */}
          <div className="mb-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] font-mono flex items-center gap-1.5">
                <Key className="w-3 h-3 text-[#58a6ff]" />
                {t.quickDemoLogin}
              </span>
              <span className="text-[9px] font-mono text-[#8b949e] bg-[#21262d] px-1.5 py-0.5 rounded border border-[#30363d]">
                1-CLICK ROLES
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {/* Badge 1: SecOps Director */}
              <button
                type="button"
                onClick={() => handleSelectRole('admin')}
                className={`p-2.5 rounded border text-left transition-colors cursor-pointer ${
                  selectedRole === 'admin'
                    ? 'bg-[#1f6feb]/15 border-[#1f6feb] text-[#f0f6fc]'
                    : 'bg-[#0d1117] border-[#21262d] hover:border-[#30363d] text-[#8b949e]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="w-5 h-5 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
                    <Shield className="w-3 h-3" />
                  </div>
                  <span
                    className={`text-[9px] font-mono font-semibold px-1 py-0.2 rounded ${
                      selectedRole === 'admin' ? 'bg-[#1f6feb] text-white' : 'bg-[#21262d] text-[#8b949e]'
                    }`}
                  >
                    LEVEL 5
                  </span>
                </div>
                <div className="text-xs font-semibold text-[#f0f6fc]">
                  {lang === 'th' ? 'SecOps ผู้นำ' : 'SecOps Dir'}
                </div>
                <div className="text-[10px] text-[#8b949e] font-mono">admin</div>
              </button>

              {/* Badge 2: Threat Analyst */}
              <button
                type="button"
                onClick={() => handleSelectRole('analyst')}
                className={`p-2.5 rounded border text-left transition-colors cursor-pointer ${
                  selectedRole === 'analyst'
                    ? 'bg-[#1f6feb]/15 border-[#1f6feb] text-[#f0f6fc]'
                    : 'bg-[#0d1117] border-[#21262d] hover:border-[#30363d] text-[#8b949e]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="w-5 h-5 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
                    <Search className="w-3 h-3" />
                  </div>
                  <span
                    className={`text-[9px] font-mono font-semibold px-1 py-0.2 rounded ${
                      selectedRole === 'analyst' ? 'bg-[#1f6feb] text-white' : 'bg-[#21262d] text-[#8b949e]'
                    }`}
                  >
                    TS // SCI
                  </span>
                </div>
                <div className="text-xs font-semibold text-[#f0f6fc]">
                  {lang === 'th' ? 'นักวิเคราะห์ภัย' : 'Analyst'}
                </div>
                <div className="text-[10px] text-[#8b949e] font-mono">analyst</div>
              </button>

              {/* Badge 3: Compliance Auditor */}
              <button
                type="button"
                onClick={() => handleSelectRole('auditor')}
                className={`p-2.5 rounded border text-left transition-colors cursor-pointer ${
                  selectedRole === 'auditor'
                    ? 'bg-[#1f6feb]/15 border-[#1f6feb] text-[#f0f6fc]'
                    : 'bg-[#0d1117] border-[#21262d] hover:border-[#30363d] text-[#8b949e]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="w-5 h-5 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
                    <Scale className="w-3 h-3" />
                  </div>
                  <span
                    className={`text-[9px] font-mono font-semibold px-1 py-0.2 rounded ${
                      selectedRole === 'auditor' ? 'bg-[#1f6feb] text-white' : 'bg-[#21262d] text-[#8b949e]'
                    }`}
                  >
                    SEC 26
                  </span>
                </div>
                <div className="text-xs font-semibold text-[#f0f6fc]">
                  {lang === 'th' ? 'ผู้ตรวจ ม.26' : 'Auditor'}
                </div>
                <div className="text-[10px] text-[#8b949e] font-mono">auditor</div>
              </button>
            </div>
          </div>

          {/* Form Credential Inputs */}
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-[#c9d1d9] flex items-center gap-1.5 font-sans">
                  <User className="w-3 h-3 text-[#58a6ff]" />
                  {t.lblUsername}
                </label>
                <span className="text-[10px] text-[#6e7681] font-mono">[AUTH_IDENTITY]</span>
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full px-3 py-2 bg-[#0d1117] border border-[#30363d] focus:border-[#1f6feb] rounded text-[#f0f6fc] font-mono text-xs focus:outline-none transition-colors placeholder:text-[#6e7681]"
                placeholder="admin / analyst / auditor"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-[#c9d1d9] flex items-center gap-1.5 font-sans">
                  <Lock className="w-3 h-3 text-[#58a6ff]" />
                  {t.lblPassword}
                </label>
                <span className="text-[10px] text-[#6e7681] font-mono">[CRYPTO_CIPHER]</span>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full pl-3 pr-10 py-2 bg-[#0d1117] border border-[#30363d] focus:border-[#1f6feb] rounded text-[#f0f6fc] font-mono text-xs focus:outline-none transition-colors placeholder:text-[#6e7681] tracking-wider"
                  placeholder="••••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#8b949e] hover:text-[#f0f6fc] cursor-pointer p-0.5"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* Action Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white font-semibold text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer transition-colors disabled:opacity-50"
            >
              <span>{loading ? t.btnLoginning : t.btnLogin}</span>
              <ArrowRight className="w-3.5 h-3.5 stroke-[2]" />
            </button>
          </form>

          {/* Legal & Crypto Accreditation Seals */}
          <div className="mt-5 pt-4 border-t border-[#21262d] flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-[#6e7681]">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3 h-3 text-[#2ea043] shrink-0" />
              <span>{t.complianceNote}</span>
            </div>
            <div className="flex items-center gap-2 text-[#8b949e]">
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3 text-[#58a6ff]" />
                FIPS-204
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <FileCheck2 className="w-3 h-3 text-[#8b949e]" />
                ISO 27001
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Accreditation Strip */}
      <footer className="flex flex-wrap items-center justify-between gap-2 max-w-7xl mx-auto w-full pt-3 border-t border-[#21262d] text-[10px] text-[#6e7681] font-mono">
        <div>
          <span>© 2026 TUM Trust Security Inc. All Rights Reserved.</span>
        </div>
        <div className="flex items-center gap-3 text-[#8b949e]">
          <span>Sovereign Air-Gap</span>
          <span>•</span>
          <span>WORM Merkle Proof</span>
          <span>•</span>
          <span>Thai CCA Sec. 26</span>
        </div>
      </footer>
    </div>
  );
};
