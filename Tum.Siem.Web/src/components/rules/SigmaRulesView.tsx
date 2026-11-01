// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState } from 'react';
import { FileCode, CheckCircle, AlertCircle, Layers, Cpu } from 'lucide-react';
import { siemApi } from '../../api/siemApi';

export const SigmaRulesView: React.FC = () => {
  const [yamlInput, setYamlInput] = useState<string>(`title: Web Application Vulnerability Scanner Detection
id: 9a8b7c6d-5e4f-3a2b-1c0d-ef9876543210
status: stable
description: Detects automated security scanners like Nikto, SQLmap, and Nuclei
level: high
tags:
    - attack.reconnaissance
    - attack.t1595.002
detection:
    selection:
        requestPath|contains:
            - '/etc/passwd'
            - '/wp-login.php'
            - '/.env'
    condition: selection
falsepositives:
    - Penetration testing authorized by CISO`);

  const [registering, setRegistering] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const activeRulesList = [
    {
      id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
      title: 'Web SQL Injection UNION SELECT Technique',
      level: 'critical',
      technique: 'T1190: Exploit Public App',
      category: 'Web Exploits',
    },
    {
      id: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
      title: 'Directory Traversal Arbitrary File Read',
      level: 'high',
      technique: 'T1083: File Discovery',
      category: 'Web Exploits',
    },
    {
      id: 'c3d4e5f6-a7b8-9012-cdef-123456789012',
      title: 'Mimikatz LSASS Memory Dump',
      level: 'critical',
      technique: 'T1003.001: LSASS Memory',
      category: 'Credential Access',
    },
    {
      id: 'd4e5f6a7-b8c9-0123-def1-234567890123',
      title: 'PowerShell Download Cradle Execution',
      level: 'high',
      technique: 'T1059.001: PowerShell',
      category: 'Execution',
    },
    {
      id: 'e5f6a7b8-c9d0-1234-ef12-345678901234',
      title: 'Multiple Failed Authentication Attempts (Brute Force)',
      level: 'medium',
      technique: 'T1110: Brute Force',
      category: 'Identity',
    },
    {
      id: 'f6a7b8c9-d0e1-2345-f123-456789012345',
      title: 'Canary Honeypot File Tampering Detection',
      level: 'critical',
      technique: 'T1486: Data Encrypted for Impact',
      category: 'Ransomware',
    },
  ];

  const handleRegister = async () => {
    setRegistering(true);
    setStatusMessage(null);
    try {
      const res = await siemApi.registerSigmaRule(yamlInput);
      setStatusMessage({
        type: 'success',
        text: `✔ คอมไพล์และลงทะเบียนกฎสำเร็จ: "${res.title}" (ID: ${res.ruleId})`,
      });
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: `❌ เกิดข้อผิดพลาดในการคอมไพล์: ${err.message}`,
      });
    } finally {
      setRegistering(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md">
          <span className="text-xs text-slate-400 font-semibold uppercase">กฎ SigmaHQ Active ในแรม</span>
          <div className="text-3xl font-black text-indigo-400 font-mono mt-1">6 + Custom</div>
          <p className="text-xs text-slate-500 mt-2">คอมไพล์เป็น .NET Expression Trees Native Instruction</p>
        </div>

        <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md">
          <span className="text-xs text-slate-400 font-semibold uppercase">ความเร็วในการประเมินกฎ</span>
          <div className="text-3xl font-black text-emerald-400 font-mono mt-1">&lt; 0.15 μs</div>
          <p className="text-xs text-slate-500 mt-2">Zero Reflection, Zero Heap Allocation per rule</p>
        </div>

        <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md">
          <span className="text-xs text-slate-400 font-semibold uppercase">มาตรฐานกฎ</span>
          <div className="text-3xl font-black text-cyan-400 font-mono mt-1">SigmaHQ v2</div>
          <p className="text-xs text-slate-500 mt-2">รองรับ MITRE ATT&CK Matrix ทันที</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Rules List */}
        <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/10">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                คลังกฎตรวจจับอัตโนมัติ (Active Sigma Rules)
              </h3>
            </div>
            <span className="text-xs font-mono text-indigo-400 font-semibold">Rules Inventory</span>
          </div>

          <div className="space-y-3 flex-grow overflow-y-auto max-h-[460px] pr-1">
            {activeRulesList.map((rule) => (
              <div
                key={rule.id}
                className="bg-slate-900/60 border border-white/5 rounded-xl p-3.5 hover:border-indigo-500/40 transition-all font-mono text-xs"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="font-bold text-white text-xs leading-snug">{rule.title}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold shrink-0 ${
                      rule.level === 'critical'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : rule.level === 'high'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
                    }`}
                  >
                    {rule.level}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-3 mt-2 text-[11px] text-slate-400">
                  <span className="text-cyan-400 font-semibold">{rule.technique}</span>
                  <span>• {rule.category}</span>
                  <span className="text-slate-600 truncate max-w-[140px]">{rule.id}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live YAML Rule Editor */}
        <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/10">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                เพิ่มกฎ Sigma แบบ Hot-Reload (YAML Editor)
              </h3>
            </div>
            <span className="text-xs font-mono text-cyan-400 font-semibold">Instant Compile</span>
          </div>

          <p className="text-xs text-slate-400 mb-3 font-sans">
            เขียนหรือวางกฎมาตรฐาน SigmaHQ เพื่อคอมไพล์เข้าสู่เมมโมรี่ของ TUM-OpenSIEM ได้ทันทีโดยไม่ต้องรีสตาร์ตระบบ
          </p>

          <textarea
            value={yamlInput}
            onChange={(e) => setYamlInput(e.target.value)}
            rows={12}
            className="w-full p-3.5 bg-slate-950 border border-white/10 rounded-xl text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500 transition-all resize-none leading-relaxed flex-grow"
          />

          {statusMessage && (
            <div
              className={`mt-3 p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                statusMessage.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}
            >
              {statusMessage.type === 'success' ? (
                <CheckCircle className="w-4 h-4 shrink-0 text-emerald-400" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              )}
              <span>{statusMessage.text}</span>
            </div>
          )}

          <div className="mt-4 flex justify-end">
            <button
              onClick={handleRegister}
              disabled={registering}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-[0_0_15px_rgba(56,189,248,0.3)] flex items-center gap-2 cursor-pointer transition-all disabled:opacity-50"
            >
              <Cpu className="w-3.5 h-3.5" />
              {registering ? 'กำลังคอมไพล์...' : 'คอมไพล์และเปิดใช้งานกฎทันที'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
