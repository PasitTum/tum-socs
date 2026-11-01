// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import {
  Globe,
  Database,
  ShieldAlert,
  Server,
  Play,
  Square,
  Activity,
  CheckCircle2,
  Lock,
  Terminal,
  Zap,
  X,
  Radio,
} from 'lucide-react';
import type { Language } from '../../i18n/translations';

interface CyberRangeModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

interface RangeStatus {
  orchestrator: string;
  active: boolean;
  layers: {
    gateway: { port: number; status: string; role: string };
    banking: { port: number; status: string; role: string };
    vault: { port: number; status: string; role: string };
    adversary: { active: boolean; role: string };
  };
  telemetryStats: {
    forwarded: number;
    threatsDetected: number;
    piiMasked: number;
    errors: number;
  };
  timestampUtc: string;
}

export const CyberRangeModal: React.FC<CyberRangeModalProps> = ({ isOpen, onClose, lang }) => {
  const [status, setStatus] = useState<RangeStatus | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:5040/range/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch {
      // Range orchestrator might be starting
    }
  };

  useEffect(() => {
    if (!isOpen) return;
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [isOpen]);

  if (!isOpen) return null;

  const handleTriggerAttack = async () => {
    setLoadingAction('attack');
    try {
      const res = await fetch('http://localhost:5040/range/attack', { method: 'POST' });
      const data = await res.json();
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] 🚨 APT ATTACK WAVE INJECTED (5 STAGES):`,
        ...(data.details || []).map((d: string) => `  ➔ ${d}`),
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ❌ ATTACK EXECUTION FAILED: ${err.message || 'Connection refused'}`,
        ...prev.slice(0, 15),
      ]);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleTriggerTraffic = async () => {
    setLoadingAction('traffic');
    try {
      const res = await fetch('http://localhost:5040/range/traffic', { method: 'POST' });
      await res.json();
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] 💳 LEGITIMATE BUSINESS TRAFFIC:`,
        `  ➔ Injected 5 payment transactions with Thai Citizen IDs & Credit Cards`,
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ❌ TRAFFIC INJECTION FAILED: ${err.message || 'Connection refused'}`,
        ...prev.slice(0, 15),
      ]);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleToggleContinuous = async () => {
    const isRunning = status?.layers.adversary.active;
    const endpoint = isRunning ? 'stop' : 'start';
    setLoadingAction('toggle');
    try {
      await fetch(`http://localhost:5040/range/continuous/${endpoint}`, { method: 'POST' });
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ⚡ Continuous Range Loop ${isRunning ? 'STOPPED' : 'STARTED (Every 2.5s)'}`,
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ❌ LOOP TOGGLE FAILED: ${err.message || 'Connection refused'}`,
        ...prev.slice(0, 15),
      ]);
    } finally {
      setLoadingAction(null);
    }
  };

  const isContinuous = status?.layers.adversary.active ?? false;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/85 backdrop-blur-md select-none">
      <div className="bg-[#080d1a] border border-cyan-500/40 rounded-3xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-[0_0_60px_rgba(56,189,248,0.25)] overflow-hidden font-sans relative">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 sm:p-6 border-b border-white/10 bg-[#0c1428]">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(56,189,248,0.3)]">
              <Radio className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base sm:text-lg font-black text-white">
                  {lang === 'th'
                    ? 'สนามจำลองระบบไซเบอร์เสมือนจริง (Enterprise Cyber Range)'
                    : 'Enterprise Sovereign Cyber Range & Threat Simulation'}
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  4 LAYERS ONLINE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {lang === 'th'
                  ? 'จำลองสถาปัตยกรรมระดับองค์กร 4 ชั้น (Gateway ➔ Banking API ➔ Database Vault ➔ Botnet) พร้อมวิเคราะห์ Log จริง'
                  : 'Multi-layer enterprise cyber ecosystem simulating real edge, business logic, DB vault, and active adversary'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-xl bg-slate-900 border border-white/10 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-6 flex-grow font-sans text-xs">
          
          {/* 1. ARCHITECTURE TOPOLOGY MAP (The 4 Layers) */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                {lang === 'th' ? 'ผังโครงสร้างสถาปัตยกรรม 4 ชั้น (Multi-Tier Architecture)' : 'Multi-Tier Cyber Infrastructure'}
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                PORT 5010 ➔ PORT 5020 ➔ PORT 5030 ➔ SIEM CORE :5000
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 relative">
              {/* Layer 1: Edge Gateway */}
              <div className="bg-[#0e172a] border border-cyan-500/30 rounded-2xl p-4 relative overflow-hidden group hover:border-cyan-400 transition-all shadow-lg">
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-xl bg-cyan-500/15 flex items-center justify-center text-cyan-400">
                    <Globe className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    PORT 5010
                  </span>
                </div>
                <div className="font-bold text-white text-sm">Layer 1: Edge Gateway</div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Reverse Proxy, SSL Offload, W3C Edge Access Logs
                </p>
                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-cyan-400 font-mono">
                  <span>NGINX/Edge Model</span>
                  <span>ONLINE</span>
                </div>
              </div>

              {/* Layer 2: Banking Core API */}
              <div className="bg-[#0e172a] border border-indigo-500/30 rounded-2xl p-4 relative overflow-hidden group hover:border-indigo-400 transition-all shadow-lg">
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-xl bg-indigo-500/15 flex items-center justify-center text-indigo-400">
                    <Server className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    PORT 5020
                  </span>
                </div>
                <div className="font-bold text-white text-sm">Layer 2: Core Banking API</div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Business Transactions, Sensitive Thai ID & PAN Data
                </p>
                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-indigo-400 font-mono">
                  <span>Business Logic</span>
                  <span>ONLINE</span>
                </div>
              </div>

              {/* Layer 3: Database & Vault */}
              <div className="bg-[#0e172a] border border-emerald-500/30 rounded-2xl p-4 relative overflow-hidden group hover:border-emerald-400 transition-all shadow-lg">
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-xl bg-emerald-500/15 flex items-center justify-center text-emerald-400">
                    <Database className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    PORT 5030
                  </span>
                </div>
                <div className="font-bold text-white text-sm">Layer 3: DB & Vault</div>
                <p className="text-[11px] text-slate-400 mt-1">
                  PostgreSQL, Honeypot Canary & Ransomware Trap
                </p>
                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-emerald-400 font-mono">
                  <span>WORM Storage</span>
                  <span>ONLINE</span>
                </div>
              </div>

              {/* Layer 4: Adversary Threat Actor */}
              <div
                className={`border rounded-2xl p-4 relative overflow-hidden transition-all shadow-lg ${
                  isContinuous
                    ? 'bg-rose-950/40 border-rose-500 shadow-[0_0_20px_rgba(244,63,94,0.3)] animate-pulse'
                    : 'bg-[#0e172a] border-rose-500/30 hover:border-rose-400'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-xl bg-rose-500/15 flex items-center justify-center text-rose-400">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      isContinuous ? 'bg-rose-500 text-white' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {isContinuous ? 'LOOP ACTIVE' : 'STANDBY'}
                  </span>
                </div>
                <div className="font-bold text-white text-sm">Layer 4: Red-Team Bot</div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Tor Exit Node 185.220.101.5, APT Campaigns, CVE Exploits
                </p>
                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-rose-400 font-mono">
                  <span>Adversary Actor</span>
                  <span>{isContinuous ? 'ATTACKING' : 'READY'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* 2. REAL-TIME TELEMETRY METRICS BAR */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#0c1428] border border-white/5 p-4 rounded-2xl font-mono">
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">TOTAL FORWARDED LOGS</span>
              <span className="text-xl font-black text-cyan-400 font-tabular">
                {(status?.telemetryStats.forwarded ?? 0).toLocaleString()}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">THREATS INTERCEPTED</span>
              <span className="text-xl font-black text-rose-400 font-tabular">
                {(status?.telemetryStats.threatsDetected ?? 0).toLocaleString()}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">PII REDACTED (PDPA)</span>
              <span className="text-xl font-black text-emerald-400 font-tabular">
                {(status?.telemetryStats.piiMasked ?? 0).toLocaleString()}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">FORWARDING ERRORS</span>
              <span className="text-xl font-black text-slate-300 font-tabular">
                {status?.telemetryStats.errors ?? 0}
              </span>
            </div>
          </div>

          {/* 3. INTERACTIVE CONTROL DECK (Fire Live Actions) */}
          <div className="bg-[#0a0f1d] border border-cyan-500/20 p-4 sm:p-5 rounded-2xl">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono mb-3 block">
              {lang === 'th' ? 'แผงสั่งการยิงสถานการณ์จำลอง (Simulation Controls):' : 'Execution Control Deck:'}
            </span>

            <div className="flex flex-wrap items-center gap-3">
              {/* Button 1: 5-Stage APT Attack Wave */}
              <button
                type="button"
                onClick={handleTriggerAttack}
                disabled={loadingAction === 'attack'}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs flex items-center gap-2 cursor-pointer shadow-[0_0_20px_rgba(244,63,94,0.3)] transition-all active:scale-95 disabled:opacity-50"
              >
                <Zap className="w-4 h-4 fill-current" />
                <span>
                  {loadingAction === 'attack'
                    ? 'กำลังยิง...'
                    : lang === 'th'
                    ? 'ยิงโจมตี 5-Stage APT Campaign'
                    : 'Launch 5-Stage APT Campaign'}
                </span>
              </button>

              {/* Button 2: Legitimate Business Traffic */}
              <button
                type="button"
                onClick={handleTriggerTraffic}
                disabled={loadingAction === 'traffic'}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-sky-600 hover:from-indigo-500 hover:to-sky-500 text-white font-bold text-xs flex items-center gap-2 cursor-pointer shadow-[0_0_20px_rgba(99,102,241,0.3)] transition-all active:scale-95 disabled:opacity-50"
              >
                <Lock className="w-4 h-4" />
                <span>
                  {loadingAction === 'traffic'
                    ? 'กำลังส่ง...'
                    : lang === 'th'
                    ? 'จำลองธุรกรรมจริง 5 รายการ (ทดสอบ PDPA)'
                    : 'Inject 5 Business Transactions (PDPA)'}
                </span>
              </button>

              {/* Button 3: Continuous Stream Loop */}
              <button
                type="button"
                onClick={handleToggleContinuous}
                disabled={loadingAction === 'toggle'}
                className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 cursor-pointer transition-all active:scale-95 disabled:opacity-50 ${
                  isContinuous
                    ? 'bg-rose-950 border border-rose-500 text-rose-300 hover:bg-rose-900'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950 shadow-[0_0_20px_rgba(16,185,129,0.3)]'
                }`}
              >
                {isContinuous ? <Square className="w-4 h-4 fill-current" /> : <Play className="w-4 h-4 fill-current" />}
                <span>
                  {isContinuous
                    ? lang === 'th'
                      ? '⏹ หยุดสตรีมมิ่งอัตโนมัติ'
                      : 'Stop Continuous Loop'
                    : lang === 'th'
                    ? '⚡ เริ่มสตรีมทราฟฟิกอัตโนมัติต่อเนื่อง (ทุก 2.5s)'
                    : 'Start Continuous Live Loop (2.5s)'}
                </span>
              </button>
            </div>
          </div>

          {/* 4. REAL-TIME ACTIVITY TERMINAL LOG */}
          <div className="bg-[#050811] border border-white/5 rounded-2xl p-4 font-mono text-[11px] space-y-1 max-h-48 overflow-y-auto">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-white/5 text-slate-500 text-[10px]">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                CYBER RANGE EXECUTION TERMINAL FEED
              </span>
              <span>LIVE BUFFER</span>
            </div>

            {logs.length === 0 ? (
              <p className="text-slate-600 italic">
                {lang === 'th'
                  ? 'ยังไม่มีการยิงคำสั่ง... กดปุ่มสั่งการด้านบนเพื่อเริ่มยิงทราฟฟิกจำลองข้ามทั้ง 4 เลเยอร์'
                  : 'Awaiting execution command... Click any button above to fire live cross-layer traffic.'}
              </p>
            ) : (
              logs.map((log, idx) => (
                <div
                  key={idx}
                  className={
                    log.includes('🚨')
                      ? 'text-rose-400 font-bold'
                      : log.includes('💳')
                      ? 'text-cyan-300 font-bold'
                      : log.includes('➔')
                      ? 'text-slate-400'
                      : 'text-emerald-400'
                  }
                >
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-[#0c1428] border-t border-white/10 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>
              {lang === 'th'
                ? 'ข้อมูลทั้งหมดถูกสตรีมเข้าสู่ TUM-OpenSIEM Core และบันทึก WORM Ledger ทันที'
                : 'All telemetry is streamed in real-time to TUM-OpenSIEM Core and secured on WORM Ledger'}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 cursor-pointer"
          >
            {lang === 'th' ? 'กลับสู่หน้าแดชบอร์ด' : 'Close Console'}
          </button>
        </div>
      </div>
    </div>
  );
};
