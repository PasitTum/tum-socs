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
  Layers,
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
        `[${new Date().toLocaleTimeString()}] [ALERT] APT ATTACK WAVE INJECTED (5 STAGES):`,
        ...(data.details || []).map((d: string) => `  -> ${d}`),
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] [ERROR] ATTACK EXECUTION FAILED: ${err.message || 'Connection refused'}`,
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
        `[${new Date().toLocaleTimeString()}] [TRANSACTION] LEGITIMATE BUSINESS TRAFFIC:`,
        `  -> Injected 5 payment transactions with Thai Citizen IDs & Credit Cards`,
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] [ERROR] TRAFFIC INJECTION FAILED: ${err.message || 'Connection refused'}`,
        ...prev.slice(0, 15),
      ]);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleToggleContinuous = async () => {
    setLoadingAction('toggle');
    const isRunning = status?.layers.adversary.active ?? false;
    try {
      const endpoint = isRunning ? '/range/stop' : '/range/start';
      const res = await fetch(`http://localhost:5040${endpoint}`, { method: 'POST' });
      await res.json();
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] [SYSTEM] Continuous Range Loop ${isRunning ? 'STOPPED' : 'STARTED (Every 2.5s)'}`,
        ...prev.slice(0, 15),
      ]);
      fetchStatus();
    } catch (err: any) {
      setLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] [ERROR] LOOP TOGGLE FAILED: ${err.message || 'Connection refused'}`,
        ...prev.slice(0, 15),
      ]);
    } finally {
      setLoadingAction(null);
    }
  };

  const isContinuous = status?.layers.adversary.active ?? false;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/75 select-none">
      <div className="bg-[#161b22] border border-[#30363d] rounded w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden font-sans relative">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#21262d] bg-[#0d1117]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm sm:text-base font-bold text-[#f0f6fc]">
                  {lang === 'th'
                    ? 'สนามจำลองระบบไซเบอร์เสมือนจริง (Enterprise Cyber Range)'
                    : 'Enterprise Sovereign Cyber Range & Threat Simulation'}
                </h3>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30">
                  4 LAYERS ONLINE
                </span>
              </div>
              <p className="text-[11px] text-[#8b949e]">
                {lang === 'th'
                  ? 'จำลองสถาปัตยกรรมระดับองค์กร 4 ชั้น (Gateway -> Banking API -> Database Vault -> Botnet) พร้อมวิเคราะห์ Log จริง'
                  : 'Multi-layer enterprise cyber ecosystem simulating real edge, business logic, DB vault, and active adversary'}
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

        {/* Modal Body */}
        <div className="p-4 sm:p-5 overflow-y-auto space-y-4 flex-grow font-sans text-xs">
          {/* 1. Architecture Topology Map */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] font-mono flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-[#58a6ff]" />
                {lang === 'th' ? 'ผังโครงสร้างสถาปัตยกรรม 4 ชั้น (Multi-Tier Architecture)' : 'Multi-Tier Cyber Infrastructure'}
              </span>
              <span className="text-[10px] font-mono text-[#6e7681]">
                {'PORT 5010 -> PORT 5020 -> PORT 5030 -> SIEM CORE :5000'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
              {/* Layer 1: Edge Gateway */}
              <div className="bg-[#0d1117] border border-[#21262d] rounded p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
                    <Globe className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30">
                    PORT 5010
                  </span>
                </div>
                <div className="font-semibold text-[#f0f6fc] text-xs">Layer 1: Edge Gateway</div>
                <p className="text-[10px] text-[#8b949e] mt-0.5">
                  Reverse Proxy, SSL Offload, W3C Edge Access Logs
                </p>
                <div className="mt-2 pt-1.5 border-t border-[#21262d] flex items-center justify-between text-[10px] text-[#58a6ff] font-mono">
                  <span>NGINX/Edge Model</span>
                  <span>ONLINE</span>
                </div>
              </div>

              {/* Layer 2: Banking Core API */}
              <div className="bg-[#0d1117] border border-[#21262d] rounded p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
                    <Server className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30">
                    PORT 5020
                  </span>
                </div>
                <div className="font-semibold text-[#f0f6fc] text-xs">Layer 2: Core Banking API</div>
                <p className="text-[10px] text-[#8b949e] mt-0.5">
                  REST APIs, JWT Auth, Fund Transfers, SQL Engine
                </p>
                <div className="mt-2 pt-1.5 border-t border-[#21262d] flex items-center justify-between text-[10px] text-[#58a6ff] font-mono">
                  <span>Express/Node Core</span>
                  <span>ONLINE</span>
                </div>
              </div>

              {/* Layer 3: Database Vault */}
              <div className="bg-[#0d1117] border border-[#21262d] rounded p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#2ea043]">
                    <Database className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded bg-[#132a1c] text-[#2ea043] border border-[#2ea043]/30">
                    PORT 5030
                  </span>
                </div>
                <div className="font-semibold text-[#f0f6fc] text-xs">Layer 3: Customer DB Vault</div>
                <p className="text-[10px] text-[#8b949e] mt-0.5">
                  Thai Citizen ID, Credit Card Vault, Masking Gate
                </p>
                <div className="mt-2 pt-1.5 border-t border-[#21262d] flex items-center justify-between text-[10px] text-[#2ea043] font-mono">
                  <span>Encrypted Ledger</span>
                  <span>SECURE</span>
                </div>
              </div>

              {/* Layer 4: Botnet Adversary */}
              <div className="bg-[#0d1117] border border-[#21262d] rounded p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="w-6 h-6 rounded bg-[#3c1e1e] flex items-center justify-center text-[#f85149]">
                    <ShieldAlert className="w-3.5 h-3.5" />
                  </div>
                  <span
                    className={`text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded border ${
                      isContinuous
                        ? 'bg-[#3c1e1e] text-[#f85149] border-[#f85149]/40'
                        : 'bg-[#21262d] text-[#8b949e] border-[#30363d]'
                    }`}
                  >
                    {isContinuous ? 'ACTIVE FIRE' : 'STANDBY'}
                  </span>
                </div>
                <div className="font-semibold text-[#f0f6fc] text-xs">Layer 4: Red-Team Botnet</div>
                <p className="text-[10px] text-[#8b949e] mt-0.5">
                  SQLi, AI Jailbreak, MCP Tool Hijack, Recon Scanners
                </p>
                <div className="mt-2 pt-1.5 border-t border-[#21262d] flex items-center justify-between text-[10px] font-mono">
                  <span className="text-[#8b949e]">Auto-Adversary</span>
                  <span className={isContinuous ? 'text-[#f85149]' : 'text-[#8b949e]'}>
                    {isContinuous ? 'LOOPING' : 'IDLE'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* 2. Live Telemetry Pipeline Metrics */}
          <div className="bg-[#0d1117] border border-[#21262d] rounded p-3.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] font-mono">
                {lang === 'th' ? 'สถิติการดักส่ง Log สด (Telemetry Forwarder Stats)' : 'Telemetry Ingestion Counters'}
              </span>
              <span className="text-[10px] font-mono text-[#58a6ff]">RFC 5424 UDP/TCP SINK</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-center">
              <div className="p-2 rounded bg-[#161b22] border border-[#21262d]">
                <span className="text-[10px] text-[#8b949e] block">Logs Forwarded</span>
                <span className="text-base font-bold text-[#f0f6fc] font-tabular">
                  {status?.telemetryStats.forwarded ?? 0}
                </span>
              </div>
              <div className="p-2 rounded bg-[#161b22] border border-[#21262d]">
                <span className="text-[10px] text-[#8b949e] block">Threats Detected</span>
                <span className="text-base font-bold text-[#f85149] font-tabular">
                  {status?.telemetryStats.threatsDetected ?? 0}
                </span>
              </div>
              <div className="p-2 rounded bg-[#161b22] border border-[#21262d]">
                <span className="text-[10px] text-[#8b949e] block">PII Masked</span>
                <span className="text-base font-bold text-[#2ea043] font-tabular">
                  {status?.telemetryStats.piiMasked ?? 0}
                </span>
              </div>
              <div className="p-2 rounded bg-[#161b22] border border-[#21262d]">
                <span className="text-[10px] text-[#8b949e] block">Delivery Errors</span>
                <span className="text-base font-bold text-[#8b949e] font-tabular">
                  {status?.telemetryStats.errors ?? 0}
                </span>
              </div>
            </div>
          </div>

          {/* 3. Action Control Matrix */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] font-mono">
                {lang === 'th' ? 'แผงควบคุมการจำลองเหตุการณ์ (Simulation Actions)' : 'Range Control Controls'}
              </span>
            </div>

            <div className="flex flex-wrap gap-2">
              {/* Button 1: Attack Wave */}
              <button
                type="button"
                onClick={handleTriggerAttack}
                disabled={loadingAction === 'attack'}
                className="px-3 py-1.5 rounded bg-[#3c1e1e] hover:bg-[#4d2525] text-[#f85149] border border-[#f85149]/40 font-semibold text-xs flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>
                  {loadingAction === 'attack'
                    ? lang === 'th' ? 'กำลังยิง...' : 'Firing...'
                    : lang === 'th' ? 'ยิงเวฟโจมตีระดับสูง (APT Wave)' : 'Trigger APT Attack Wave'}
                </span>
              </button>

              {/* Button 2: Normal Traffic */}
              <button
                type="button"
                onClick={handleTriggerTraffic}
                disabled={loadingAction === 'traffic'}
                className="px-3 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] border border-[#30363d] font-semibold text-xs flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5 text-[#2ea043]" />
                <span>
                  {loadingAction === 'traffic'
                    ? lang === 'th' ? 'กำลังส่งข้อมูล...' : 'Sending...'
                    : lang === 'th' ? 'จำลองธุรกรรมธนาคารปกติ (PDPA Masking Test)' : 'Simulate Business Transactions (PDPA)'}
                </span>
              </button>

              {/* Button 3: Continuous Stream Loop */}
              <button
                type="button"
                onClick={handleToggleContinuous}
                disabled={loadingAction === 'toggle'}
                className={`px-3 py-1.5 rounded font-semibold text-xs flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50 ${
                  isContinuous
                    ? 'bg-[#3c1e1e] border border-[#f85149]/40 text-[#f85149] hover:bg-[#4d2525]'
                    : 'bg-[#1f6feb] hover:bg-[#388bfd] text-white'
                }`}
              >
                {isContinuous ? <Square className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                <span>
                  {isContinuous
                    ? lang === 'th'
                      ? 'หยุดสตรีมมิ่งอัตโนมัติ'
                      : 'Stop Continuous Loop'
                    : lang === 'th'
                    ? 'เริ่มสตรีมทราฟฟิกอัตโนมัติต่อเนื่อง (ทุก 2.5s)'
                    : 'Start Continuous Live Loop (2.5s)'}
                </span>
              </button>
            </div>
          </div>

          {/* 4. Real-Time Activity Terminal Log */}
          <div className="bg-[#0d1117] border border-[#21262d] rounded p-3 font-mono text-[11px] space-y-1 max-h-44 overflow-y-auto">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-[#21262d] text-[#6e7681] text-[10px]">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3 h-3 text-[#58a6ff]" />
                CYBER RANGE EXECUTION TERMINAL FEED
              </span>
              <span>LIVE BUFFER</span>
            </div>

            {logs.length === 0 ? (
              <p className="text-[#6e7681] italic">
                {lang === 'th'
                  ? 'ยังไม่มีการยิงคำสั่ง... กดปุ่มสั่งการด้านบนเพื่อเริ่มยิงทราฟฟิกจำลองข้ามทั้ง 4 เลเยอร์'
                  : 'Awaiting execution command... Click any button above to fire live cross-layer traffic.'}
              </p>
            ) : (
              logs.map((log, idx) => (
                <div
                  key={idx}
                  className={
                    log.includes('[ALERT]')
                      ? 'text-[#f85149] font-semibold'
                      : log.includes('[TRANSACTION]')
                      ? 'text-[#58a6ff]'
                      : log.includes('[ERROR]')
                      ? 'text-[#d29922]'
                      : 'text-[#2ea043]'
                  }
                >
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-[#0d1117] border-t border-[#21262d] flex items-center justify-between text-[11px] font-mono text-[#8b949e]">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-[#2ea043]" />
            <span>
              {lang === 'th'
                ? 'ข้อมูลทั้งหมดถูกสตรีมเข้าสู่ TUM-OpenSIEM Core และบันทึก WORM Ledger ทันที'
                : 'All telemetry is streamed in real-time to TUM-OpenSIEM Core and secured on WORM Ledger'}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1 rounded bg-[#21262d] text-[#c9d1d9] hover:text-white font-medium cursor-pointer border border-[#30363d]"
          >
            {lang === 'th' ? 'กลับสู่หน้าแดชบอร์ด' : 'Close Console'}
          </button>
        </div>
      </div>
    </div>
  );
};
