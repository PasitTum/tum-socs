// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React from 'react';
import { ShieldAlert, Activity, EyeOff, Layers, Zap, Lock, ShieldCheck } from 'lucide-react';
import type { ThreatDashboardSummary, SystemStatus } from '../../types/siem';
import { translations, type Language } from '../../i18n/translations';

interface MetricCardsProps {
  summary: ThreatDashboardSummary | null;
  status: SystemStatus | null;
  lang?: Language;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ summary, status, lang = 'th' }) => {
  const t = translations[lang];

  const totalEvents = summary?.totalEventsIngested ?? 0;
  const blockedThreats = (summary?.criticalAlertsCount ?? 0) + (summary?.highAlertsCount ?? 0);
  const activeRules = status?.activeSigmaRules ?? summary?.activeSigmaRulesCount ?? 6;
  const piiRedacted = summary?.totalPiiRedacted ?? 0;
  const eps = summary?.currentEventsPerSecond ?? 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* 1. Ingestion Traffic / Total Logs */}
      <div className="bg-[#0b101e]/80 border border-cyan-500/20 hover:border-cyan-500/50 rounded-2xl p-5 backdrop-blur-xl relative overflow-hidden group transition-all duration-300 shadow-lg shadow-cyan-950/20">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-80" />
        
        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            {t.metricTotalLogs}
          </span>
          <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        <div className="text-3xl font-black text-white font-mono tracking-tight font-tabular mb-2 flex items-baseline gap-2">
          <span>{totalEvents.toLocaleString()}</span>
          <span className="text-xs font-normal text-slate-400 font-sans">
            {lang === 'th' ? 'เหตุการณ์' : 'events'}
          </span>
        </div>

        <div className="flex items-center justify-between text-xs pt-2 border-t border-white/5">
          <span className="text-emerald-400 font-semibold font-mono flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-beacon" />
            {eps > 0 ? `${eps.toFixed(1)} EPS` : '8.8M EPS Capable'}
          </span>
          <span className="text-slate-500 font-mono text-[10px]">
            {t.zeroTax}
          </span>
        </div>
      </div>

      {/* 2. Blocked Threats / Intercepted Exploits */}
      <div className="bg-[#0b101e]/80 border border-rose-500/20 hover:border-rose-500/50 rounded-2xl p-5 backdrop-blur-xl relative overflow-hidden group transition-all duration-300 shadow-lg shadow-rose-950/20">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-rose-500 to-transparent opacity-80" />

        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            {t.metricBlockedThreats}
          </span>
          <div className="w-8 h-8 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 group-hover:scale-110 transition-transform">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>

        <div className="text-3xl font-black text-rose-400 font-mono tracking-tight font-tabular mb-2 flex items-baseline gap-2">
          <span>{blockedThreats.toLocaleString()}</span>
          <span className="text-xs font-normal text-rose-400/70 font-sans">
            {lang === 'th' ? 'สกัดกั้นสำเร็จ' : 'mitigated'}
          </span>
        </div>

        <div className="flex items-center justify-between text-xs pt-2 border-t border-white/5">
          <span className="text-rose-400 font-semibold font-mono flex items-center gap-1">
            <Zap className="w-3 h-3" />
            0.12 ms
          </span>
          <span className="text-slate-500 font-mono text-[10px]">
            {t.autoMitigated}
          </span>
        </div>
      </div>

      {/* 3. Active SigmaHQ Rules */}
      <div className="bg-[#0b101e]/80 border border-indigo-500/20 hover:border-indigo-500/50 rounded-2xl p-5 backdrop-blur-xl relative overflow-hidden group transition-all duration-300 shadow-lg shadow-indigo-950/20">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-80" />

        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            {t.metricActiveRules}
          </span>
          <div className="w-8 h-8 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 group-hover:scale-110 transition-transform">
            <Layers className="w-4 h-4" />
          </div>
        </div>

        <div className="text-3xl font-black text-indigo-400 font-mono tracking-tight font-tabular mb-2 flex items-baseline gap-2">
          <span>{activeRules}</span>
          <span className="text-xs font-normal text-indigo-300/70 font-sans">
            {t.openRules}
          </span>
        </div>

        <div className="flex items-center justify-between text-xs pt-2 border-t border-white/5">
          <span className="text-indigo-300 font-semibold font-mono flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" />
            In-Memory AST
          </span>
          <span className="text-slate-500 font-mono text-[10px]">
            MITRE ATT&CK
          </span>
        </div>
      </div>

      {/* 4. PII Redacted / Privacy Guard (PDPA) */}
      <div className="bg-[#0b101e]/80 border border-emerald-500/20 hover:border-emerald-500/50 rounded-2xl p-5 backdrop-blur-xl relative overflow-hidden group transition-all duration-300 shadow-lg shadow-emerald-950/20">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-400 to-transparent opacity-80" />

        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            {t.metricPiiRedacted}
          </span>
          <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 group-hover:scale-110 transition-transform">
            <EyeOff className="w-4 h-4" />
          </div>
        </div>

        <div className="text-3xl font-black text-emerald-400 font-mono tracking-tight font-tabular mb-2 flex items-baseline gap-2">
          <span>{piiRedacted.toLocaleString()}</span>
          <span className="text-xs font-normal text-emerald-400/70 font-sans">
            {lang === 'th' ? 'รายการกำบัง' : 'redacted'}
          </span>
        </div>

        <div className="flex items-center justify-between text-xs pt-2 border-t border-white/5">
          <span className="text-emerald-400 font-semibold font-mono flex items-center gap-1">
            <Lock className="w-3 h-3" />
            Thai ID & PAN
          </span>
          <span className="text-slate-500 font-mono text-[10px]">
            AI Sanitizer
          </span>
        </div>
      </div>
    </div>
  );
};
