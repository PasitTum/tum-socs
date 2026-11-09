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
    <div className="flex flex-col h-full p-4 select-none relative z-20">
      {/* Brand Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[#21262d] mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-[#1f6feb] flex items-center justify-center text-white shrink-0">
            <Shield className="w-5 h-5 fill-current" />
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-tight text-[#f0f6fc]">
              {t.brandName}
            </h2>
            <span className="text-[10px] font-mono text-[#8b949e] uppercase tracking-wider block">
              {t.brandSubtitle}
            </span>
          </div>
        </div>

        {/* Mobile Close Button */}
        {onCloseMobile && (
          <button
            type="button"
            onClick={onCloseMobile}
            className="lg:hidden p-1.5 rounded bg-[#161b22] border border-[#30363d] text-[#8b949e] hover:text-white cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Navigation Items */}
      <nav className="flex flex-col gap-1 flex-grow">
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
              className={`flex items-center gap-3 px-3 py-2.5 rounded text-left transition-colors cursor-pointer ${
                isActive
                  ? 'bg-[#161b22] text-[#f0f6fc] font-semibold border-l-2 border-[#1f6feb]'
                  : 'text-[#8b949e] hover:text-[#f0f6fc] hover:bg-[#161b22]/50 border-l-2 border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#58a6ff]' : 'text-[#8b949e]'}`} />
              <div className="flex flex-col overflow-hidden">
                <span className="text-xs leading-tight truncate">{item.label}</span>
                <span className="text-[10px] text-[#6e7681] font-mono truncate">{item.subtitle}</span>
              </div>
            </button>
          );
        })}
      </nav>

      {/* Authenticated User & System Status Box */}
      <div className="mt-auto pt-3 border-t border-[#21262d] space-y-2">
        {/* User Card */}
        {user && (
          <div className="bg-[#161b22] border border-[#21262d] rounded p-2.5 flex items-center gap-2.5">
            <div className="w-7 h-7 rounded bg-[#21262d] text-[#8b949e] flex items-center justify-center shrink-0">
              <UserCheck className="w-4 h-4" />
            </div>
            <div className="overflow-hidden">
              <span className="text-xs font-semibold text-[#f0f6fc] block truncate">{user.fullName}</span>
              <span className="text-[10px] text-[#8b949e] font-mono block truncate">
                Role: {user.role}
              </span>
            </div>
          </div>
        )}

        {/* Engine Status Box */}
        <div className="bg-[#161b22] border border-[#21262d] rounded p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-[#8b949e] flex items-center gap-1.5 font-mono">
              <Radio className="w-3 h-3 text-[#2ea043]" />
              {t.engineStatus}
            </span>
            <span className="text-[9px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#2ea043]/15 text-[#2ea043] font-semibold border border-[#2ea043]/30">
              {status?.status ?? 'OPERATIONAL'}
            </span>
          </div>

          <div className="text-[10px] text-[#8b949e] space-y-1 font-mono">
            <div className="flex items-center justify-between">
              <span className="text-[#6e7681]">{t.wormSeal}</span>
              <span className="text-[#2ea043] font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> CCA Sec 26
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#6e7681]">{t.retention}</span>
              <span className="text-[#c9d1d9] font-medium">
                {status?.wormRetentionDays ?? 90} {t.days}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#6e7681]">{t.sigmaRules}</span>
              <span className="text-[#c9d1d9] font-medium">
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
      <aside className="hidden lg:flex w-64 bg-[#0d1117] border-r border-[#21262d] shrink-0 min-h-screen">
        {sidebarContent}
      </aside>

      {/* Mobile & Tablet Slide-out Drawer Overlay */}
      {isMobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="fixed inset-0 bg-black/70 backdrop-blur-none transition-opacity"
            onClick={onCloseMobile}
          />
          <div className="fixed inset-y-0 left-0 w-72 max-w-[85vw] bg-[#0d1117] border-r border-[#30363d] flex flex-col z-50">
            {sidebarContent}
          </div>
        </div>
      )}
    </>
  );
};
