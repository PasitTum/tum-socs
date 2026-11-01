// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import { Search, Filter, ShieldCheck, Copy, Database, Check } from 'lucide-react';
import { siemApi } from '../../api/siemApi';
import type { EventQueryResult, TumLogEntry } from '../../types/siem';

export const LogExplorerView: React.FC = () => {
  const [query, setQuery] = useState<string>('*');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<EventQueryResult | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<TumLogEntry | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const executeSearch = async (searchTerm = query) => {
    setLoading(true);
    try {
      const data = await siemApi.queryLogs(searchTerm, 100, 0);
      setResult(data);
    } catch (err) {
      console.error('Search failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeSearch('*');
  }, []);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const sampleQueries = [
    { label: 'All Logs (*)', q: '*' },
    { label: 'Critical Threats', q: 'Severity=Critical' },
    { label: 'SQL Injection', q: 'PayloadSanitized LIKE %UNION%' },
    { label: 'Tor Exit Node', q: 'ClientIp=185.220.101.5' },
    { label: 'PII Redacted', q: 'PiiRedactedCount > 0' },
  ];

  return (
    <div className="space-y-6">
      {/* Search Header Bar */}
      <div className="bg-[#111827]/70 border border-white/10 rounded-2xl p-5 backdrop-blur-md space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeSearch();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-grow">
            <Search className="w-5 h-5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="ค้นหา Log ด้วยไวยากรณ์ Lucene หรือ SQL (เช่น Severity=Critical, ClientIp=185.220.101.5, หรือ *)..."
              className="w-full pl-11 pr-4 py-3 bg-slate-900 border border-white/10 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-cyan-500 transition-all placeholder:text-slate-600"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-sm shadow-[0_0_15px_rgba(56,189,248,0.25)] flex items-center justify-center gap-2 cursor-pointer transition-all disabled:opacity-50"
          >
            <Filter className="w-4 h-4" />
            {loading ? 'กำลังค้นหา...' : 'สืบค้น Log'}
          </button>
        </form>

        {/* Query Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-white/5 text-xs">
          <span className="text-slate-500 font-semibold">ตัวอย่างคำค้น:</span>
          {sampleQueries.map((item) => (
            <button
              key={item.label}
              onClick={() => {
                setQuery(item.q);
                executeSearch(item.q);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700/80 border border-white/5 font-mono text-[11px] transition-all cursor-pointer"
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Diagnostics & Query Speed */}
        {result && (
          <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 font-mono bg-slate-950/40 p-2.5 rounded-lg border border-white/5">
            <div className="flex items-center gap-3">
              <span>สแกนพบ: <strong className="text-white">{result.totalMatched}</strong> รายการ</span>
              <span>• ความเร็ว: <strong className="text-emerald-400">{result.executionDurationMs.toFixed(2)} ms</strong></span>
              <span>• ตรวจสอบทั้งหมด: <strong className="text-slate-300">{result.totalScanned}</strong> รายการ</span>
            </div>
            {result.translatedSqlWhere && (
              <div className="flex items-center gap-1.5 text-cyan-400/90 text-[11px]">
                <Database className="w-3.5 h-3.5" />
                <span>SQL Translated: {result.translatedSqlWhere}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Log Data Table */}
      <div className="bg-[#111827]/70 border border-white/10 rounded-2xl backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-white/10">
              <tr>
                <th className="py-3.5 px-4">Timestamp (UTC)</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">Client IP</th>
                <th className="py-3.5 px-4">Event / Action</th>
                <th className="py-3.5 px-4">Sanitized Content</th>
                <th className="py-3.5 px-4">WORM SHA-256 Hash</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {!result || result.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                    ไม่พบข้อมูลเหตุการณ์ที่ตรงกับเงื่อนไขการค้นหา
                  </td>
                </tr>
              ) : (
                result.items.map((entry) => {
                  const isCritical = entry.severity === 'Critical';
                  const isWarning = entry.severity === 'Warning';
                  const isCopied = copiedHash === entry.tamperProofHash;

                  return (
                    <tr
                      key={entry.logId}
                      className="hover:bg-white/[0.03] transition-colors group cursor-pointer"
                      onClick={() => setSelectedEntry(entry)}
                    >
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(entry.timestampUtc).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isCritical
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : isWarning
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {entry.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-cyan-300 font-bold whitespace-nowrap">
                        {entry.clientIp}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="text-white font-semibold">{entry.eventName}</span>
                        {entry.requestPath && (
                          <span className="text-slate-400 text-[11px] block">{entry.httpMethod} {entry.requestPath}</span>
                        )}
                      </td>
                      <td className="py-3 px-4 max-w-xs truncate text-slate-400">
                        {entry.payloadSanitized}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[11px] text-slate-500 truncate max-w-[140px]">
                            {entry.tamperProofHash || 'SHA-256 PENDING'}
                          </span>
                          {entry.tamperProofHash && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(entry.tamperProofHash);
                              }}
                              className="text-slate-500 hover:text-cyan-400 p-1"
                              title="คัดลอกแฮชพยานหลักฐาน"
                            >
                              {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEntry(entry);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] transition-all cursor-pointer"
                        >
                          ตรวจสอบ
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entry Modal Detail Drawer */}
      {selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0B0E1A] border border-cyan-500/40 rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-mono">
            <div className="flex items-center justify-between p-5 border-b border-white/10 bg-slate-900/60">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-base font-bold text-white">
                  รายละเอียดพยานหลักฐานทางนิติวิทยาศาสตร์ดิจิทัล (Log Inspection)
                </h3>
              </div>
              <button
                onClick={() => setSelectedEntry(null)}
                className="text-slate-400 hover:text-white text-lg p-1"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-4 rounded-xl border border-white/5">
                <div>
                  <span className="text-slate-500 block">Log ID:</span>
                  <span className="text-white font-bold">{selectedEntry.logId}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Timestamp (NTP Stratum 1 Synchronized):</span>
                  <span className="text-emerald-400">{selectedEntry.timestampUtc}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Client IP (Sec 26 Custody):</span>
                  <span className="text-cyan-400 font-bold">{selectedEntry.clientIp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Severity & Category:</span>
                  <span className="text-rose-400 font-bold">{selectedEntry.severity} (Cat: {selectedEntry.category})</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Cryptographic Chain of Custody:</span>
                <div className="bg-slate-950 p-3 rounded-lg border border-white/5 space-y-1 text-[11px]">
                  <div><strong className="text-slate-500">TamperProof Hash:</strong> <span className="text-cyan-300">{selectedEntry.tamperProofHash}</span></div>
                  <div><strong className="text-slate-500">Merkle Root:</strong> <span className="text-indigo-300">{selectedEntry.merkleRoot}</span></div>
                  <div><strong className="text-slate-500">Previous Entry Hash:</strong> <span className="text-slate-400">{selectedEntry.previousEntryHash}</span></div>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Sanitized Payload (PII Redacted: {selectedEntry.piiRedactedCount}):</span>
                <pre className="bg-slate-950 p-3 rounded-lg border border-white/5 text-slate-200 overflow-x-auto text-[11px] whitespace-pre-wrap">
                  {selectedEntry.payloadSanitized}
                </pre>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Full Technical JSON:</span>
                <pre className="bg-slate-950 p-3 rounded-lg border border-white/5 text-slate-400 overflow-x-auto text-[10px]">
                  {JSON.stringify(selectedEntry, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-4 border-t border-white/10 bg-slate-900/60 flex justify-end gap-3">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-5 py-2 rounded-xl bg-slate-800 text-slate-300 hover:text-white cursor-pointer"
              >
                ปิดหน้าต่าง
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
