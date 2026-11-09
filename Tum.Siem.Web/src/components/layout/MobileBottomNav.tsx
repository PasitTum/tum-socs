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
    <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#0d1117] border-t border-[#21262d] px-3 py-1.5 flex items-center justify-around">
      {items.slice(0, 2).map((item) => {
        const Icon = item.icon;
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onTabChange(item.id)}
            className={`flex flex-col items-center justify-center min-w-[50px] min-h-[40px] rounded transition-colors ${
              isActive ? 'text-[#58a6ff] font-semibold' : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span className="text-[10px] mt-0.5 font-mono">{item.label}</span>
          </button>
        );
      })}

      {/* Center Action: Red-Team Simulate Attack Button */}
      <button
        type="button"
        onClick={onOpenSimulator}
        title={t.btnSimulate}
        className="flex flex-col items-center justify-center w-9 h-9 rounded bg-[#3c1e1e] hover:bg-[#4d2525] text-[#f85149] border border-[#f85149]/40 cursor-pointer transition-colors"
      >
        <Play className="w-4 h-4 fill-current ml-0.5" />
      </button>

      {items.slice(2).map((item) => {
        const Icon = item.icon;
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onTabChange(item.id)}
            className={`flex flex-col items-center justify-center min-w-[50px] min-h-[40px] rounded transition-colors ${
              isActive ? 'text-[#58a6ff] font-semibold' : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span className="text-[10px] mt-0.5 font-mono">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
};
