// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import {
  Play,
  Download,
  RefreshCw,
  Clock,
  Database,
  LogOut,
  Menu,
  Activity,
  Search,
  Network,
  FileCode,
  Scale,
  Layers,
  Boxes,
} from 'lucide-react';
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

  const tabMeta: Record<ActiveTab, { title: string; subtitle: string; icon: React.FC<{ className?: string }> }> = {
    radar: {
      title: t.radarTitle,
      subtitle: t.radarSubtitle,
      icon: Activity,
    },
    explorer: {
      title: t.explorerTitle,
      subtitle: t.explorerSubtitle,
      icon: Search,
    },
    graph: {
      title: t.graphTitle,
      subtitle: t.graphSubtitle,
      icon: Network,
    },
    rules: {
      title: t.rulesTitle,
      subtitle: t.rulesSubtitle,
      icon: FileCode,
    },
    compliance: {
      title: t.complianceTitle,
      subtitle: t.complianceSubtitle,
      icon: Scale,
    },
    deployment: {
      title: t.deploymentTitle,
      subtitle: t.deploymentSubtitle,
      icon: Boxes,
    },
  };

  const currentMeta = tabMeta[activeTab];
  const CurrentIcon = currentMeta.icon;

  return (
    <header className="flex flex-wrap items-center justify-between gap-3 pb-4 mb-4 border-b border-[#21262d] select-none">
      <div className="flex items-start gap-2.5">
        {onToggleMobileMenu && (
          <button
            type="button"
            onClick={onToggleMobileMenu}
            className="lg:hidden p-1.5 rounded bg-[#161b22] border border-[#30363d] text-[#8b949e] hover:text-white cursor-pointer mt-0.5"
            aria-label="Open Navigation Menu"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <CurrentIcon className="w-4 h-4 text-[#58a6ff]" />
            <h1 className="text-base lg:text-lg font-bold text-[#f0f6fc] tracking-tight">
              {currentMeta.title}
            </h1>
          </div>
          <p className="text-[11px] text-[#8b949e] font-sans max-w-2xl line-clamp-1 sm:line-clamp-none">
            {currentMeta.subtitle}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {/* DEFCON Status Pill */}
        <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded bg-[#161b22] border border-[#30363d] text-[11px] font-mono font-medium text-[#c9d1d9]">
          <span className="w-2 h-2 rounded-full bg-[#2ea043]" />
          <span>DEFCON 2 // MESH ACTIVE</span>
        </div>

        {/* Live NTP Clock */}
        <div className="hidden 2xl:flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#161b22] border border-[#21262d] text-[11px] font-mono text-[#8b949e] font-tabular">
          <Clock className="w-3 h-3 text-[#58a6ff]" />
          <span>{currentTime}</span>
        </div>

        {/* Language Switcher */}
        <div className="flex items-center bg-[#161b22] border border-[#30363d] rounded p-0.5">
          <button
            type="button"
            onClick={() => onLanguageChange('th')}
            className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
              lang === 'th'
                ? 'bg-[#1f6feb] text-white'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            TH
          </button>
          <button
            type="button"
            onClick={() => onLanguageChange('en')}
            className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
              lang === 'en'
                ? 'bg-[#1f6feb] text-white'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            EN
          </button>
        </div>

        {/* Enterprise Cyber Range Button */}
        <button
          type="button"
          onClick={onOpenCyberRange}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium text-[#c9d1d9] bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] transition-colors cursor-pointer"
        >
          <Layers className="w-3.5 h-3.5 text-[#58a6ff]" />
          <span>{t.btnCyberRange}</span>
        </button>

        {/* Real Datasets & Clean Prod Button */}
        <button
          type="button"
          onClick={onOpenDatasets}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium text-[#c9d1d9] bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] transition-colors cursor-pointer"
        >
          <Database className="w-3.5 h-3.5 text-[#8b949e]" />
          <span>{t.btnDatasets}</span>
        </button>

        {/* Attack Simulator Button */}
        <button
          type="button"
          onClick={onOpenSimulator}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium text-[#f85149] bg-[#3c1e1e] hover:bg-[#4d2525] border border-[#f85149]/40 transition-colors cursor-pointer"
        >
          <Play className="w-3 h-3 fill-current" />
          <span>{t.btnSimulate}</span>
        </button>

        {/* Full Scan Button */}
        <button
          type="button"
          onClick={onTriggerScan}
          disabled={isScanning}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium text-[#c9d1d9] bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#58a6ff] ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? t.btnScanning : t.btnScan}</span>
        </button>

        {/* Export Compliance Audit */}
        <button
          type="button"
          onClick={onExportAudit}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium text-white bg-[#1f6feb] hover:bg-[#388bfd] transition-colors cursor-pointer"
        >
          <Download className="w-3.5 h-3.5 stroke-[2]" />
          <span>{t.btnExport}</span>
        </button>

        {/* Logout Button */}
        <button
          type="button"
          onClick={onLogout}
          title={t.btnLogout}
          className="p-1.5 rounded bg-[#161b22] hover:bg-[#3c1e1e] hover:text-[#f85149] border border-[#30363d] text-[#8b949e] transition-colors cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
