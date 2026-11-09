// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  ShieldX,
  Terminal,
  Cpu,
  Lock,
  X,
  Fingerprint,
} from 'lucide-react';
import type { TumLogEntry } from '../../types/siem';
import { translations, type Language } from '../../i18n/translations';

interface LiveAttackFeedProps {
  events: TumLogEntry[];
  lang?: Language;
}

export const LiveAttackFeed: React.FC<LiveAttackFeedProps> = ({ events, lang = 'th' }) => {
  const [selectedEvent, setSelectedEvent] = useState<TumLogEntry | null>(null);
  const [filter, setFilter] = useState<'all' | 'threats' | 'pii'>('all');
  const t = translations[lang];

  const filteredEvents = events.filter((ev) => {
    if (filter === 'threats') {
      return ev.severity === 'Critical' || (ev.securityThreats && ev.securityThreats.length > 0);
    }
    if (filter === 'pii') {
      return ev.piiRedactedCount > 0;
    }
    return true;
  });

  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded p-4 flex flex-col h-[500px] relative">
      {/* Feed Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
            <Terminal className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-[#f0f6fc] uppercase tracking-wider font-mono">
              {t.liveFeedTitle}
            </h3>
            <p className="text-[10px] text-[#8b949e] font-mono">
              WORM MERKLE STREAM // ZERO INGESTION TAX
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1 font-mono text-[11px] bg-[#0d1117] p-0.5 rounded border border-[#21262d]">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors cursor-pointer ${
              filter === 'all'
                ? 'bg-[#1f6feb] text-white'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            {lang === 'th' ? 'ทั้งหมด' : 'All'} ({events.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('threats')}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors cursor-pointer ${
              filter === 'threats'
                ? 'bg-[#f85149] text-white'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            {lang === 'th' ? 'ภัยคุกคาม' : 'Threats'}
          </button>
          <button
            type="button"
            onClick={() => setFilter('pii')}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors cursor-pointer ${
              filter === 'pii'
                ? 'bg-[#2ea043] text-white'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            PDPA
          </button>
        </div>
      </div>

      {/* Feed Stream */}
      <div className="flex-grow overflow-y-auto space-y-1.5 pr-1 font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-[#6e7681] space-y-2">
            <Cpu className="w-8 h-8 text-[#30363d]" />
            <p className="text-xs font-semibold text-[#8b949e] font-sans">{t.waitingTelemetry}</p>
            <p className="text-[11px] text-[#6e7681] font-sans max-w-sm text-center">
              {t.simHint}
            </p>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isCritical =
              ev.severity === 'Critical' || (ev.securityThreats && ev.securityThreats.length > 0);
            const isWarning = ev.severity === 'Warning';
            const timeStr = new Date(ev.timestampUtc).toTimeString().split(' ')[0];

            return (
              <div
                key={ev.logId}
                onClick={() => setSelectedEvent(ev)}
                className={`p-2.5 rounded border transition-colors cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 ${
                  isCritical
                    ? 'bg-[#3c1e1e]/40 border-[#f85149]/30 hover:border-[#f85149]/60'
                    : isWarning
                    ? 'bg-[#2b220c]/40 border-[#d29922]/30 hover:border-[#d29922]/60'
                    : 'bg-[#0d1117] border-[#21262d] hover:border-[#30363d]'
                }`}
              >
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <div className="shrink-0">
                    {isCritical ? (
                      <div className="w-5 h-5 rounded bg-[#3c1e1e] flex items-center justify-center text-[#f85149]">
                        <ShieldX className="w-3.5 h-3.5" />
                      </div>
                    ) : isWarning ? (
                      <div className="w-5 h-5 rounded bg-[#2b220c] flex items-center justify-center text-[#d29922]">
                        <AlertTriangle className="w-3.5 h-3.5" />
                      </div>
                    ) : (
                      <div className="w-5 h-5 rounded bg-[#132a1c] flex items-center justify-center text-[#2ea043]">
                        <CheckCircle className="w-3.5 h-3.5" />
                      </div>
                    )}
                  </div>

                  <div className="truncate">
                    <div className="flex items-center gap-2 font-tabular text-[11px]">
                      <span className="text-[#6e7681]">{timeStr}</span>
                      <span className="text-[#c9d1d9] font-medium">{ev.clientIp}</span>
                      <span className="text-[#58a6ff]">
                        {ev.httpMethod ?? 'POST'} {ev.requestPath ?? ev.eventName}
                      </span>
                    </div>
                    <div className="text-[10px] text-[#8b949e] truncate mt-0.5">
                      {ev.payloadSanitized || ev.eventName}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-center">
                  {ev.piiRedactedCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30 flex items-center gap-1 font-semibold">
                      <Lock className="w-2.5 h-2.5 text-[#2ea043]" />
                      PDPA ({ev.piiRedactedCount})
                    </span>
                  )}
                  <span
                    className={`px-1.5 py-0.5 rounded text-[9px] font-semibold tracking-wide border ${
                      isCritical
                        ? 'bg-[#3c1e1e] text-[#f85149] border-[#f85149]/40'
                        : isWarning
                        ? 'bg-[#2b220c] text-[#d29922] border-[#d29922]/40'
                        : 'bg-[#132a1c] text-[#2ea043] border-[#2ea043]/30'
                    }`}
                  >
                    {isCritical ? 'CRITICAL' : isWarning ? 'SUSPICIOUS' : 'VERIFIED WORM'}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* FORENSIC INSPECTOR MODAL */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#161b22] border border-[#30363d] rounded p-5 relative">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#21262d]">
              <div className="flex items-center gap-2">
                <Fingerprint className="w-4 h-4 text-[#58a6ff]" />
                <h3 className="text-sm font-bold text-[#f0f6fc] font-mono">
                  {lang === 'th' ? 'การสืบค้นพยานหลักฐานทางนิติวิทยาศาสตร์' : 'Forensic Custody Inspection'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
                className="text-[#8b949e] hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 bg-[#0d1117] rounded border border-[#21262d]">
                  <span className="text-[#6e7681] block">Log ID:</span>
                  <span className="text-[#f0f6fc] font-bold">{selectedEvent.logId}</span>
                </div>
                <div className="p-2 bg-[#0d1117] rounded border border-[#21262d]">
                  <span className="text-[#6e7681] block">Client IP:</span>
                  <span className="text-[#f0f6fc] font-bold">{selectedEvent.clientIp}</span>
                </div>
              </div>

              <div className="p-2.5 bg-[#0d1117] rounded border border-[#21262d]">
                <span className="text-[#6e7681] block mb-1">Sanitized Event Payload:</span>
                <p className="text-[#58a6ff] break-all leading-relaxed">
                  {selectedEvent.payloadSanitized || selectedEvent.eventName}
                </p>
              </div>

              <div className="p-2.5 bg-[#0d1117] rounded border border-[#21262d]">
                <span className="text-[#6e7681] block mb-1">WORM SHA-256 Merkle Proof:</span>
                <p className="text-[#2ea043] break-all">
                  {selectedEvent.tamperProofHash || 'SHA-256 PENDING'}
                </p>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedEvent(null)}
                  className="px-3 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] text-xs font-medium cursor-pointer"
                >
                  {lang === 'th' ? 'ปิด' : 'Close'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
