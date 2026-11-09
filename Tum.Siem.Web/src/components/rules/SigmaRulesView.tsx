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
        text: `คอมไพล์และลงทะเบียนกฎสำเร็จ: "${res.title}" (ID: ${res.ruleId})`,
      });
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: `เกิดข้อผิดพลาดในการคอมไพล์: ${err.message}`,
      });
    } finally {
      setRegistering(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-[#161b22] border border-[#21262d] rounded p-4">
          <span className="text-[11px] text-[#8b949e] font-semibold uppercase">กฎ SigmaHQ Active ในแรม</span>
          <div className="text-2xl font-bold text-[#58a6ff] font-mono mt-1">6 + Custom</div>
          <p className="text-[11px] text-[#6e7681] mt-1.5">คอมไพล์เป็น .NET Expression Trees Native Instruction</p>
        </div>

        <div className="bg-[#161b22] border border-[#21262d] rounded p-4">
          <span className="text-[11px] text-[#8b949e] font-semibold uppercase">ความเร็วในการประเมินกฎ</span>
          <div className="text-2xl font-bold text-[#2ea043] font-mono mt-1">&lt; 0.15 μs</div>
          <p className="text-[11px] text-[#6e7681] mt-1.5">Zero Reflection, Zero Heap Allocation per rule</p>
        </div>

        <div className="bg-[#161b22] border border-[#21262d] rounded p-4">
          <span className="text-[11px] text-[#8b949e] font-semibold uppercase">มาตรฐานกฎ</span>
          <div className="text-2xl font-bold text-[#f0f6fc] font-mono mt-1">SigmaHQ v2</div>
          <p className="text-[11px] text-[#6e7681] mt-1.5">รองรับ MITRE ATT&CK Matrix ทันที</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Active Rules List */}
        <div className="bg-[#161b22] border border-[#21262d] rounded p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#21262d]">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#58a6ff]" />
              <h3 className="text-xs font-bold text-[#f0f6fc] uppercase tracking-wider">
                คลังกฎตรวจจับอัตโนมัติ (Active Sigma Rules)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-[#8b949e] font-semibold">Rules Inventory</span>
          </div>

          <div className="space-y-2 flex-grow overflow-y-auto max-h-[460px] pr-1">
            {activeRulesList.map((rule) => (
              <div
                key={rule.id}
                className="bg-[#0d1117] border border-[#21262d] rounded p-3 hover:border-[#30363d] transition-colors font-mono text-xs"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="font-semibold text-[#f0f6fc] text-xs leading-snug">{rule.title}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[9px] uppercase font-semibold shrink-0 border ${
                      rule.level === 'critical'
                        ? 'bg-[#3c1e1e] text-[#f85149] border-[#f85149]/40'
                        : rule.level === 'high'
                        ? 'bg-[#2b220c] text-[#d29922] border-[#d29922]/40'
                        : 'bg-[#162a3a] text-[#58a6ff] border-[#58a6ff]/30'
                    }`}
                  >
                    {rule.level}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 mt-2 text-[10px] text-[#8b949e]">
                  <span className="text-[#58a6ff] font-medium">{rule.technique}</span>
                  <span>• {rule.category}</span>
                  <span className="text-[#6e7681] truncate max-w-[140px]">{rule.id}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live YAML Rule Editor */}
        <div className="bg-[#161b22] border border-[#21262d] rounded p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#21262d]">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-[#58a6ff]" />
              <h3 className="text-xs font-bold text-[#f0f6fc] uppercase tracking-wider">
                เพิ่มกฎ Sigma แบบ Hot-Reload (YAML Editor)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-[#58a6ff] font-semibold">Instant Compile</span>
          </div>

          <p className="text-[11px] text-[#8b949e] mb-2 font-sans">
            เขียนหรือวางกฎมาตรฐาน SigmaHQ เพื่อคอมไพล์เข้าสู่เมมโมรี่ของ TUM-OpenSIEM ได้ทันทีโดยไม่ต้องรีสตาร์ตระบบ
          </p>

          <textarea
            value={yamlInput}
            onChange={(e) => setYamlInput(e.target.value)}
            rows={12}
            className="w-full p-3 bg-[#0d1117] border border-[#30363d] rounded text-[#c9d1d9] font-mono text-xs focus:outline-none focus:border-[#1f6feb] transition-colors resize-none leading-relaxed flex-grow"
          />

          {statusMessage && (
            <div
              className={`mt-2.5 p-2 rounded border text-xs font-mono flex items-center gap-2 ${
                statusMessage.type === 'success'
                  ? 'bg-[#132a1c] border-[#2ea043]/30 text-[#2ea043]'
                  : 'bg-[#3c1e1e] border-[#f85149]/40 text-[#f85149]'
              }`}
            >
              {statusMessage.type === 'success' ? (
                <CheckCircle className="w-4 h-4 shrink-0 text-[#2ea043]" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0 text-[#f85149]" />
              )}
              <span>{statusMessage.text}</span>
            </div>
          )}

          <div className="mt-3 flex justify-end">
            <button
              onClick={handleRegister}
              disabled={registering}
              className="px-4 py-2 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white font-medium text-xs flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
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
