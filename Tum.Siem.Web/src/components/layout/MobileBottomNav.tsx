// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React from 'react';
import { Shield, Search, Network, Scale, Play } from 'lucide-react';
import type { ActiveTab } from './Sidebar';
import { translations, type Language } from '../../i18n/translations';

interface MobileBottomNavProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onOpenSimulator: () => void;
  lang: Language;
}

export const MobileBottomNav: React.FC<MobileBottomNavProps> = ({
  activeTab,
  onTabChange,
  onOpenSimulator,
  lang,
}) => {
  const t = translations[lang];

  const items = [
    { id: 'radar' as ActiveTab, label: lang === 'th' ? 'เรดาร์' : 'Radar', icon: Shield },
    { id: 'explorer' as ActiveTab, label: lang === 'th' ? 'ค้นหา' : 'Search', icon: Search },
    { id: 'graph' as ActiveTab, label: lang === 'th' ? 'กราฟ' : 'Graph', icon: Network },
    { id: 'compliance' as ActiveTab, label: lang === 'th' ? 'ม.26' : 'Audit', icon: Scale },
  ];

  return (
    <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#060a14]/95 backdrop-blur-xl border-t border-white/10 px-3 py-2 flex items-center justify-around shadow-[0_-5px_25px_rgba(0,0,0,0.5)]">
      {items.slice(0, 2).map((item) => {
        const Icon = item.icon;
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onTabChange(item.id)}
            className={`flex flex-col items-center justify-center min-w-[54px] min-h-[44px] rounded-xl transition-all ${
              isActive ? 'text-cyan-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Icon className={`w-5 h-5 ${isActive ? 'stroke-[2.5]' : ''}`} />
            <span className="text-[10px] mt-1 font-mono">{item.label}</span>
          </button>
        );
      })}

      {/* Center Action: Red-Team Simulate Attack Button */}
      <button
        type="button"
        onClick={onOpenSimulator}
        title={t.btnSimulate}
        className="flex flex-col items-center justify-center w-12 h-12 -mt-4 rounded-2xl bg-gradient-to-tr from-rose-600 to-amber-500 text-white shadow-[0_0_20px_rgba(244,63,94,0.4)] active:scale-95 transition-transform cursor-pointer border border-rose-400/30"
      >
        <Play className="w-5 h-5 fill-current ml-0.5" />
      </button>

      {items.slice(2).map((item) => {
        const Icon = item.icon;
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onTabChange(item.id)}
            className={`flex flex-col items-center justify-center min-w-[54px] min-h-[44px] rounded-xl transition-all ${
              isActive ? 'text-cyan-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Icon className={`w-5 h-5 ${isActive ? 'stroke-[2.5]' : ''}`} />
            <span className="text-[10px] mt-1 font-mono">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
};
