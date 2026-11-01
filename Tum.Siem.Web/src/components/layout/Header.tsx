// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import { Play, Download, RefreshCw, Clock, Globe, Database, LogOut, Menu } from 'lucide-react';
import type { ActiveTab } from './Sidebar';
import { translations, type Language } from '../../i18n/translations';

interface HeaderProps {
  activeTab: ActiveTab;
  onOpenSimulator: () => void;
  onOpenDatasets: () => void;
  onOpenCyberRange: () => void;
  onExportAudit: () => void;
  onTriggerScan: () => void;
  onLogout: () => void;
  isScanning: boolean;
  lang: Language;
  onLanguageChange: (lang: Language) => void;
  onToggleMobileMenu?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onOpenSimulator,
  onOpenDatasets,
  onOpenCyberRange,
  onExportAudit,
  onTriggerScan,
  onLogout,
  isScanning,
  lang,
  onLanguageChange,
  onToggleMobileMenu,
}) => {
  const [currentTime, setCurrentTime] = useState<string>('');
  const t = translations[lang];

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setCurrentTime(now.toTimeString().split(' ')[0] + ' UTC+7');
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const tabTitles: Record<ActiveTab, { title: string; subtitle: string; icon: string }> = {
    radar: {
      title: t.radarTitle,
      subtitle: t.radarSubtitle,
      icon: '⚡',
    },
    explorer: {
      title: t.explorerTitle,
      subtitle: t.explorerSubtitle,
      icon: '🔍',
    },
    graph: {
      title: t.graphTitle,
      subtitle: t.graphSubtitle,
      icon: '🕸️',
    },
    rules: {
      title: t.rulesTitle,
      subtitle: t.rulesSubtitle,
      icon: '📜',
    },
    compliance: {
      title: t.complianceTitle,
      subtitle: t.complianceSubtitle,
      icon: '⚖️',
    },
  };

  const currentMeta = tabTitles[activeTab];

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 pb-6 mb-6 border-b border-white/5 select-none relative">
      <div className="flex items-start gap-3">
        {onToggleMobileMenu && (
          <button
            type="button"
            onClick={onToggleMobileMenu}
            className="lg:hidden p-2 rounded-xl bg-slate-900 border border-white/10 text-cyan-400 hover:text-white cursor-pointer mt-0.5"
            aria-label="Open Navigation Menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm">{currentMeta.icon}</span>
            <h1 className="text-lg lg:text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
              <span>{currentMeta.title}</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 font-sans max-w-2xl line-clamp-2 sm:line-clamp-none">
            {currentMeta.subtitle}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        {/* DEFCON Status Pill */}
        <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-cyan-500/30 text-xs font-mono font-bold text-cyan-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-beacon" />
          <span>DEFCON 2 // MESH ACTIVE</span>
        </div>

        {/* Live NTP Clock */}
        <div className="hidden 2xl:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-white/10 text-xs font-mono text-slate-300 font-tabular">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime}</span>
        </div>

        {/* Language Switcher */}
        <div className="flex items-center gap-1 bg-slate-900/90 border border-cyan-500/30 p-1 rounded-xl shadow-lg">
          <Globe className="w-3.5 h-3.5 text-cyan-400 ml-1.5 mr-0.5" />
          <button
            type="button"
            onClick={() => onLanguageChange('th')}
            className={`px-2 py-0.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              lang === 'th' ? 'bg-cyan-500 text-slate-950 font-extrabold shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            🇹🇭 TH
          </button>
          <button
            type="button"
            onClick={() => onLanguageChange('en')}
            className={`px-2 py-0.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              lang === 'en' ? 'bg-cyan-500 text-slate-950 font-extrabold shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            🇺🇸 EN
          </button>
        </div>

        {/* Enterprise Cyber Range Button */}
        <button
          type="button"
          onClick={onOpenCyberRange}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold text-slate-950 bg-gradient-to-r from-cyan-400 via-sky-400 to-indigo-300 hover:from-cyan-300 hover:to-indigo-200 transition-all shadow-[0_0_20px_rgba(56,189,248,0.35)] cursor-pointer active:scale-95"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-beacon" />
          <span>{t.btnCyberRange}</span>
        </button>

        {/* Real Datasets & Clean Prod Button */}
        <button
          type="button"
          onClick={onOpenDatasets}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-500 transition-all shadow-[0_0_20px_rgba(99,102,241,0.35)] cursor-pointer active:scale-95"
        >
          <Database className="w-3.5 h-3.5 text-indigo-200" />
          <span>{t.btnDatasets}</span>
        </button>

        {/* Attack Simulator Button */}
        <button
          type="button"
          onClick={onOpenSimulator}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-rose-600 via-rose-500 to-amber-600 hover:from-rose-500 hover:to-amber-500 transition-all shadow-[0_0_20px_rgba(244,63,94,0.35)] cursor-pointer active:scale-95"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>{t.btnSimulate}</span>
        </button>

        {/* Full Scan Button */}
        <button
          type="button"
          onClick={onTriggerScan}
          disabled={isScanning}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold text-slate-200 bg-[#0d1424] hover:bg-slate-800 border border-white/10 hover:border-cyan-500/40 transition-all cursor-pointer disabled:opacity-50 active:scale-95"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? t.btnScanning : t.btnScan}</span>
        </button>

        {/* Export Compliance Audit */}
        <button
          type="button"
          onClick={onExportAudit}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold text-slate-950 bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 transition-all shadow-[0_0_20px_rgba(56,189,248,0.35)] cursor-pointer active:scale-95"
        >
          <Download className="w-3.5 h-3.5 stroke-[2.5]" />
          <span>{t.btnExport}</span>
        </button>

        {/* Logout Button */}
        <button
          type="button"
          onClick={onLogout}
          title={t.btnLogout}
          className="p-2 rounded-xl bg-[#0d1424] hover:bg-rose-950/60 border border-white/10 hover:border-rose-500/40 text-slate-400 hover:text-rose-400 transition-all cursor-pointer active:scale-95"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
