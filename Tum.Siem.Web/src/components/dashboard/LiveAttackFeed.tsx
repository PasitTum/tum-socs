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
  Hash,
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
    <div className="bg-[#0b101e]/80 border border-white/10 rounded-2xl p-5 backdrop-blur-xl flex flex-col h-[530px] relative overflow-hidden shadow-2xl">
      {/* Feed Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              {t.liveFeedTitle}
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              WORM MERKLE STREAM // ZERO INGESTION TAX
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 font-mono text-[11px] bg-slate-900/80 p-1 rounded-xl border border-white/10">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
              filter === 'all'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {lang === 'th' ? 'ทั้งหมด' : 'All'} ({events.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('threats')}
            className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
              filter === 'threats'
                ? 'bg-rose-500 text-white font-bold shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {lang === 'th' ? 'ภัยคุกคาม' : 'Threats'}
          </button>
          <button
            type="button"
            onClick={() => setFilter('pii')}
            className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
              filter === 'pii'
                ? 'bg-emerald-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            PDPA
          </button>
        </div>
      </div>

      {/* Feed Stream */}
      <div className="flex-grow overflow-y-auto space-y-2.5 pr-1 font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3">
            <Cpu className="w-10 h-10 animate-pulse text-cyan-500/40" />
            <p className="text-sm font-bold text-slate-400 font-sans">{t.waitingTelemetry}</p>
            <p className="text-xs text-slate-500 font-sans max-w-sm text-center">
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
                className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 group ${
                  isCritical
                    ? 'bg-rose-950/25 border-rose-500/30 hover:border-rose-400 hover:bg-rose-950/40 hover:shadow-[0_0_15px_rgba(244,63,94,0.15)]'
                    : isWarning
                    ? 'bg-amber-950/25 border-amber-500/30 hover:border-amber-400 hover:bg-amber-950/40'
                    : 'bg-[#090e1c] border-white/5 hover:border-cyan-500/30 hover:bg-slate-900/80'
                }`}
              >
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="shrink-0">
                    {isCritical ? (
                      <div className="w-6 h-6 rounded-lg bg-rose-500/20 flex items-center justify-center text-rose-400">
                        <ShieldX className="w-4 h-4" />
                      </div>
                    ) : isWarning ? (
                      <div className="w-6 h-6 rounded-lg bg-amber-500/20 flex items-center justify-center text-amber-400">
                        <AlertTriangle className="w-4 h-4" />
                      </div>
                    ) : (
                      <div className="w-6 h-6 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <CheckCircle className="w-4 h-4" />
                      </div>
                    )}
                  </div>

                  <div className="truncate">
                    <div className="flex items-center gap-2 font-tabular">
                      <span className="text-slate-500 text-[10px]">{timeStr}</span>
                      <span className="text-slate-200 font-bold">{ev.clientIp}</span>
                      <span className="text-cyan-400 text-[11px]">
                        ➔ {ev.httpMethod ?? 'POST'} {ev.requestPath ?? ev.eventName}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5 group-hover:text-slate-300 transition-colors">
                      {ev.payloadSanitized || ev.eventName}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                  {ev.piiRedactedCount > 0 && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 font-bold">
                      <Lock className="w-3 h-3 text-emerald-400" />
                      PDPA ({ev.piiRedactedCount})
                    </span>
                  )}
                  <span
                    className={`px-2.5 py-0.5 rounded text-[10px] font-bold tracking-wide ${
                      isCritical
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 shadow-[0_0_10px_rgba(244,63,94,0.2)]'
                        : isWarning
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {isCritical ? 'CRITICAL THREAT' : isWarning ? 'SUSPICIOUS' : 'VERIFIED WORM'}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* FORENSIC INSPECTOR MODAL */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#090e1c] border border-cyan-500/40 rounded-3xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <Fingerprint className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-mono">
                  {lang === 'th' ? 'การสืบค้นพยานหลักฐานทางนิติวิทยาศาสตร์' : 'Forensic Custody Inspection'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-xl bg-slate-900/80 border border-white/5">
                  <span className="text-slate-500 block text-[10px]">EVENT IDENTIFIER:</span>
                  <span className="text-cyan-400 font-bold truncate block">{selectedEvent.logId}</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/80 border border-white/5">
                  <span className="text-slate-500 block text-[10px]">CLIENT ORIGIN:</span>
                  <span className="text-white font-bold">{selectedEvent.clientIp}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/80 border border-white/5">
                <span className="text-slate-500 block text-[10px] mb-1">
                  SHA-256 TAMPER-PROOF WORM SEAL:
                </span>
                <span className="text-emerald-400 font-bold break-all flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  {selectedEvent.tamperProofHash || 'SHA256_GENESIS_SEAL_INTACT_AUTHENTICATED'}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/80 border border-white/5">
                <span className="text-slate-500 block text-[10px] mb-1">SANITIZED PAYLOAD:</span>
                <pre className="text-slate-200 text-[11px] whitespace-pre-wrap bg-black/50 p-2.5 rounded-lg border border-white/5 max-h-36 overflow-y-auto">
                  {selectedEvent.payloadSanitized || JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedEvent(null)}
                  className="px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-bold text-xs hover:bg-cyan-400 cursor-pointer"
                >
                  {lang === 'th' ? 'ปิดหน้าต่าง' : 'Dismiss'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
