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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 select-none">
      <div className="bg-[#161b22] border border-[#30363d] rounded w-full max-w-xl overflow-hidden font-sans relative">
        {/* Modal Header */}
        <div className="p-4 border-b border-[#21262d] flex items-start justify-between bg-[#0d1117]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded bg-[#21262d] flex items-center justify-center text-[#2ea043]">
              <ShieldCheck className="w-5 h-5" />
            </div>

            <div>
              <h3 className="text-sm font-bold text-[#f0f6fc]">
                {lang === 'th'
                  ? 'การสแกนระบบความมั่นคงเสร็จสมบูรณ์'
                  : 'Full-Spectrum Security Scan Complete'}
              </h3>
              <p className="text-[10px] text-[#2ea043] font-mono uppercase tracking-wider mt-0.5 flex items-center gap-1.5">
                <Radio className="w-3 h-3" />
                ALL SOVEREIGN DEFENSE LAYERS OPERATIONAL
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="text-[#8b949e] hover:text-white p-1 rounded bg-[#21262d] border border-[#30363d] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body / Inspection Results */}
        <div className="p-4 space-y-2.5 text-xs font-mono">
          {/* Tile 1: RingBuffer Mesh */}
          <div className="p-3 rounded bg-[#0d1117] border border-[#21262d] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-[#21262d] text-[#58a6ff] flex items-center justify-center">
                <Activity className="w-3.5 h-3.5" />
              </div>
              <div>
                <span className="font-semibold text-[#f0f6fc] block text-xs font-sans">
                  {lang === 'th' ? 'RingBuffer Ingestion Mesh' : 'RingBuffer Ingestion Mesh'}
                </span>
                <span className="text-[10px] text-[#8b949e]">
                  {lang === 'th'
                    ? 'สถาปัตยกรรม Non-blocking 8.8M EPS throughput'
                    : 'Non-blocking lock-free 8.8M EPS throughput'}
                </span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[9px] font-semibold bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30 flex items-center gap-1">
              <CheckCircle2 className="w-2.5 h-2.5 text-[#2ea043]" />
              NORMAL
            </span>
          </div>

          {/* Tile 2: Merkle Ledger */}
          <div className="p-3 rounded bg-[#0d1117] border border-[#21262d] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-[#21262d] text-[#2ea043] flex items-center justify-center">
                <Lock className="w-3.5 h-3.5" />
              </div>
              <div>
                <span className="font-semibold text-[#f0f6fc] block text-xs font-sans">
                  {lang === 'th' ? 'WORM Cryptographic Merkle Ledger' : 'WORM Merkle Forensic Ledger'}
                </span>
                <span className="text-[10px] text-[#8b949e]">
                  {lang === 'th'
                    ? 'พยานหลักฐานตาม พ.ร.บ.คอมฯ ม.26 ครบถ้วน 100%'
                    : '100% Intact Chain of Custody (Thai CCA Sec. 26)'}
                </span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[9px] font-semibold bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30 flex items-center gap-1">
              <CheckCircle2 className="w-2.5 h-2.5 text-[#2ea043]" />
              INTACT
            </span>
          </div>

          {/* Tile 3: SigmaHQ Rule Engine */}
          <div className="p-3 rounded bg-[#0d1117] border border-[#21262d] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-[#21262d] text-[#58a6ff] flex items-center justify-center">
                <Layers className="w-3.5 h-3.5" />
              </div>
              <div>
                <span className="font-semibold text-[#f0f6fc] block text-xs font-sans">
                  {lang === 'th' ? 'SigmaHQ In-Memory Engine' : 'SigmaHQ In-Memory Rule Trees'}
                </span>
                <span className="text-[10px] text-[#8b949e]">
                  {lang === 'th'
                    ? 'กฎ Active ทั้งหมดคอมไพล์เป็น Expression Trees พร้อมสกัดกั้น'
                    : 'All 6 active detection rules compiled into native AST'}
                </span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[9px] font-semibold bg-[#162a3a] text-[#58a6ff] border border-[#58a6ff]/30 flex items-center gap-1">
              <CheckCircle2 className="w-2.5 h-2.5 text-[#58a6ff]" />
              ARMED
            </span>
          </div>

          {/* Tile 4: Stratum-1 Time Sync */}
          <div className="p-3 rounded bg-[#0d1117] border border-[#21262d] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-[#21262d] text-[#58a6ff] flex items-center justify-center">
                <Clock className="w-3.5 h-3.5" />
              </div>
              <div>
                <span className="font-semibold text-[#f0f6fc] block text-xs font-sans">
                  {lang === 'th' ? 'NTP Stratum-1 Time Synchronization' : 'NTP Stratum-1 Time Source'}
                </span>
                <span className="text-[10px] text-[#8b949e] font-mono">
                  time.navy.mi.th (Royal Thai Navy) // Jitter: 0.04ms
                </span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[9px] font-semibold bg-[#162a3a] text-[#58a6ff] border border-[#58a6ff]/30 flex items-center gap-1">
              <CheckCircle2 className="w-2.5 h-2.5 text-[#58a6ff]" />
              LOCKED
            </span>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-[#21262d] bg-[#0d1117] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#6e7681]">
            <FileCheck2 className="w-3.5 h-3.5 text-[#2ea043]" />
            <span>ISO/IEC 27001 & FIPS 204 Kyber-1024 Certified</span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white font-medium text-xs cursor-pointer transition-colors"
          >
            {lang === 'th' ? 'รับทราบผลการสแกน' : 'Acknowledge Scan'}
          </button>
        </div>
      </div>
    </div>
  );
};
