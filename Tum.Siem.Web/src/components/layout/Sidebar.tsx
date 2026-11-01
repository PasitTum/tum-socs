// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React from 'react';
import {
  Shield,
  Search,
  Network,
  FileCode,
  Scale,
  CheckCircle2,
  UserCheck,
  Radio,
  X,
} from 'lucide-react';
import type { SystemStatus } from '../../types/siem';
import type { UserProfile } from '../../types/auth';
import { translations, type Language } from '../../i18n/translations';

export type ActiveTab = 'radar' | 'explorer' | 'graph' | 'rules' | 'compliance';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  status: SystemStatus | null;
  user: UserProfile | null;
  lang: Language;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  status,
  user,
  lang,
  isMobileOpen = false,
  onCloseMobile,
}) => {
  const t = translations[lang];

  const navItems = [
    { id: 'radar' as ActiveTab, label: t.navRadar, subtitle: t.navRadarSub, icon: Shield },
    { id: 'explorer' as ActiveTab, label: t.navExplorer, subtitle: t.navExplorerSub, icon: Search },
    { id: 'graph' as ActiveTab, label: t.navGraph, subtitle: t.navGraphSub, icon: Network },
    { id: 'rules' as ActiveTab, label: t.navRules, subtitle: t.navRulesSub, icon: FileCode },
    { id: 'compliance' as ActiveTab, label: t.navCompliance, subtitle: t.navComplianceSub, icon: Scale },
  ];

  const sidebarContent = (
    <div className="flex flex-col h-full p-5 select-none relative z-20">
      {/* Brand Header */}
      <div className="flex items-center justify-between pb-6 border-b border-white/5 mb-6">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-cyan-500 via-sky-500 to-indigo-600 flex items-center justify-center font-black text-slate-950 text-xl shadow-[0_0_20px_rgba(56,189,248,0.4)]">
              <Shield className="w-6 h-6 text-slate-950 fill-current" />
            </div>
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-[#050814] animate-beacon" />
          </div>
          <div>
            <h2 className="text-base font-black tracking-tight text-white flex items-center gap-1.5">
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-sky-200 to-indigo-400">
                {t.brandName}
              </span>
            </h2>
            <span className="text-[10px] font-bold text-cyan-400 tracking-wider uppercase block font-mono">
              {t.brandSubtitle}
            </span>
          </div>
        </div>

        {/* Mobile Close Button */}
        {onCloseMobile && (
          <button
            type="button"
            onClick={onCloseMobile}
            className="lg:hidden p-1.5 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Navigation Items */}
      <nav className="flex flex-col gap-2 flex-grow">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onTabChange(item.id);
                onCloseMobile?.();
              }}
              className={`flex items-center gap-3.5 px-4 py-3 rounded-2xl text-left transition-all duration-200 cursor-pointer relative group ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/15 to-transparent text-cyan-300 font-bold border-l-4 border-cyan-400 shadow-[inset_0_0_15px_rgba(56,189,248,0.1)]'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <div
                className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 transition-transform ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-400'
                    : 'bg-white/5 text-slate-400 group-hover:scale-105'
                }`}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div className="flex flex-col overflow-hidden">
                <span className="text-sm leading-tight truncate">{item.label}</span>
                <span className="text-[10px] text-slate-500 font-mono truncate">{item.subtitle}</span>
              </div>
            </button>
          );
        })}
      </nav>

      {/* Authenticated User & System Status Box */}
      <div className="mt-auto pt-4 border-t border-white/5 space-y-3">
        {/* User Card */}
        {user && (
          <div className="bg-[#0b1020] border border-white/5 rounded-2xl p-3 flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 text-cyan-300 flex items-center justify-center font-bold text-xs shrink-0">
              <UserCheck className="w-4 h-4" />
            </div>
            <div className="overflow-hidden">
              <span className="text-xs font-bold text-white block truncate">{user.fullName}</span>
              <span className="text-[10px] text-cyan-400 font-mono block truncate">
                Role: {user.role}
              </span>
            </div>
          </div>
        )}

        {/* Engine Status Box */}
        <div className="bg-[#0b1020] border border-white/5 rounded-2xl p-3.5 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5 font-mono">
              <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              {t.engineStatus}
            </span>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
              {status?.status ?? 'OPERATIONAL'}
            </span>
          </div>

          <div className="text-[11px] text-slate-400 space-y-1.5 font-mono">
            <div className="flex items-center justify-between">
              <span className="text-slate-500">{t.wormSeal}</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> CCA Sec 26
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">{t.retention}</span>
              <span className="text-cyan-400 font-bold">
                {status?.wormRetentionDays ?? 90} {t.days}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">{t.sigmaRules}</span>
              <span className="text-indigo-400 font-bold">
                {status?.activeSigmaRules ?? 6} {t.loaded}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Persistent Sidebar */}
      <aside className="hidden lg:flex w-72 bg-[#050814] border-r border-white/5 shrink-0 min-h-screen">
        {sidebarContent}
      </aside>

      {/* Mobile & Tablet Slide-out Drawer Overlay */}
      {isMobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={onCloseMobile}
          />
          <div className="fixed inset-y-0 left-0 w-80 max-w-[85vw] bg-[#050814] border-r border-white/10 shadow-2xl flex flex-col z-50">
            {sidebarContent}
          </div>
        </div>
      )}
    </>
  );
};
