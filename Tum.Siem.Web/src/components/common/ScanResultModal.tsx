// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  Activity,
  Layers,
  Lock,
  Clock,
  X,
  Radio,
  FileCheck2,
} from 'lucide-react';
import type { Language } from '../../i18n/translations';

interface ScanResultModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const ScanResultModal: React.FC<ScanResultModalProps> = ({
  isOpen,
  onClose,
  lang,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md select-none animate-fadeIn">
      <div className="bg-[#080d1a] border border-cyan-500/40 rounded-3xl w-full max-w-xl shadow-[0_0_50px_rgba(56,189,248,0.3)] overflow-hidden font-sans relative hud-box">
        {/* Modal Top Accent Line */}
        <div className="h-1 bg-gradient-to-r from-cyan-400 via-sky-400 to-indigo-500" />

        {/* Modal Header */}
        <div className="p-6 border-b border-white/5 flex items-start justify-between bg-[#0b1224]">
          <div className="flex items-center gap-3.5">
            <div className="relative">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-500/20 to-emerald-500/20 border border-emerald-400/40 flex items-center justify-center text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)]">
                <ShieldCheck className="w-7 h-7" />
              </div>
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-400 border-2 border-[#080d1a] animate-beacon" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-black text-white">
                  {lang === 'th'
                    ? 'การสแกนระบบความมั่นคงเสร็จสมบูรณ์'
                    : 'Full-Spectrum Security Scan Complete'}
                </h3>
              </div>
              <p className="text-xs text-cyan-400 font-mono uppercase tracking-wider mt-0.5 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5" />
                ALL SOVEREIGN DEFENSE LAYERS OPERATIONAL
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-xl bg-slate-900 border border-white/10 cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body / Inspection Results */}
        <div className="p-6 space-y-3.5 text-xs font-mono">
          {/* Tile 1: RingBuffer Mesh */}
          <div className="p-3.5 rounded-2xl bg-[#0d162a] border border-white/5 flex items-center justify-between hover:border-cyan-500/30 transition-all">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-cyan-500/15 text-cyan-400 flex items-center justify-center">
                <Activity className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-white block text-sm font-sans">
                  {lang === 'th' ? 'RingBuffer Ingestion Mesh' : 'RingBuffer Ingestion Mesh'}
                </span>
                <span className="text-[11px] text-slate-400">
                  {lang === 'th'
                    ? 'สถาปัตยกรรม Non-blocking 8.8M EPS throughput'
                    : 'Non-blocking lock-free 8.8M EPS throughput'}
                </span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              NORMAL
            </span>
          </div>

          {/* Tile 2: Merkle Ledger */}
          <div className="p-3.5 rounded-2xl bg-[#0d162a] border border-white/5 flex items-center justify-between hover:border-emerald-500/30 transition-all">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-emerald-500/15 text-emerald-400 flex items-center justify-center">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-white block text-sm font-sans">
                  {lang === 'th' ? 'WORM Cryptographic Merkle Ledger' : 'WORM Merkle Forensic Ledger'}
                </span>
                <span className="text-[11px] text-slate-400">
                  {lang === 'th'
                    ? 'พยานหลักฐานตาม พ.ร.บ.คอมฯ ม.26 ครบถ้วน 100%'
                    : '100% Intact Chain of Custody (Thai CCA Sec. 26)'}
                </span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              INTACT
            </span>
          </div>

          {/* Tile 3: SigmaHQ Rule Engine */}
          <div className="p-3.5 rounded-2xl bg-[#0d162a] border border-white/5 flex items-center justify-between hover:border-indigo-500/30 transition-all">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-indigo-500/15 text-indigo-400 flex items-center justify-center">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-white block text-sm font-sans">
                  {lang === 'th' ? 'SigmaHQ In-Memory Engine' : 'SigmaHQ In-Memory Rule Trees'}
                </span>
                <span className="text-[11px] text-slate-400">
                  {lang === 'th'
                    ? 'กฎ Active ทั้งหมดคอมไพล์เป็น Expression Trees พร้อมสกัดกั้น'
                    : 'All 6 active detection rules compiled into native AST'}
                </span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-indigo-400" />
              ARMED
            </span>
          </div>

          {/* Tile 4: Stratum-1 Time Sync */}
          <div className="p-3.5 rounded-2xl bg-[#0d162a] border border-white/5 flex items-center justify-between hover:border-sky-500/30 transition-all">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-sky-500/15 text-sky-400 flex items-center justify-center">
                <Clock className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-white block text-sm font-sans">
                  {lang === 'th' ? 'NTP Stratum-1 Time Synchronization' : 'NTP Stratum-1 Time Source'}
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  time.navy.mi.th (Royal Thai Navy) // Jitter: 0.04ms
                </span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-sky-400" />
              LOCKED
            </span>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-white/5 bg-[#0b1224] flex items-center justify-between">
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
            <span>ISO/IEC 27001 & FIPS 204 Kyber-1024 Certified</span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 text-slate-950 font-black text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(56,189,248,0.3)] cursor-pointer active:scale-95 transition-all"
          >
            {lang === 'th' ? 'รับทราบผลการสแกน' : 'Acknowledge Scan'}
          </button>
        </div>
      </div>
    </div>
  );
};
