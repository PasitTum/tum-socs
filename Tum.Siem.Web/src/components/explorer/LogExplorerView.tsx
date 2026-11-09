// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import { Search, Filter, ShieldCheck, Copy, Database, Check, X } from 'lucide-react';
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
    <div className="space-y-4">
      {/* Search Header Bar */}
      <div className="bg-[#161b22] border border-[#21262d] rounded p-4 space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeSearch();
          }}
          className="flex flex-col sm:flex-row gap-2"
        >
          <div className="relative flex-grow">
            <Search className="w-4 h-4 text-[#8b949e] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="ค้นหา Log ด้วยไวยากรณ์ Lucene หรือ SQL (เช่น Severity=Critical, ClientIp=185.220.101.5, หรือ *)..."
              className="w-full pl-9 pr-3 py-2 bg-[#0d1117] border border-[#30363d] rounded text-[#f0f6fc] font-mono text-xs focus:outline-none focus:border-[#1f6feb] transition-colors placeholder:text-[#6e7681]"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white font-medium text-xs flex items-center justify-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
          >
            <Filter className="w-3.5 h-3.5" />
            {loading ? 'กำลังค้นหา...' : 'สืบค้น Log'}
          </button>
        </form>

        {/* Query Presets */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-[#21262d] text-xs">
          <span className="text-[#8b949e] text-[11px] font-medium">ตัวอย่างคำค้น:</span>
          {sampleQueries.map((item) => (
            <button
              key={item.label}
              onClick={() => {
                setQuery(item.q);
                executeSearch(item.q);
              }}
              className="px-2 py-0.5 rounded bg-[#21262d] text-[#c9d1d9] hover:text-white hover:bg-[#30363d] border border-[#30363d] font-mono text-[10px] transition-colors cursor-pointer"
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Diagnostics & Query Speed */}
        {result && (
          <div className="flex flex-wrap items-center justify-between text-[11px] text-[#8b949e] font-mono bg-[#0d1117] p-2 rounded border border-[#21262d]">
            <div className="flex items-center gap-3">
              <span>สแกนพบ: <strong className="text-[#f0f6fc]">{result.totalMatched}</strong> รายการ</span>
              <span>• ความเร็ว: <strong className="text-[#2ea043]">{result.executionDurationMs.toFixed(2)} ms</strong></span>
              <span>• ตรวจสอบทั้งหมด: <strong className="text-[#c9d1d9]">{result.totalScanned}</strong> รายการ</span>
            </div>
            {result.translatedSqlWhere && (
              <div className="flex items-center gap-1.5 text-[#58a6ff] text-[10px]">
                <Database className="w-3 h-3" />
                <span>SQL: {result.translatedSqlWhere}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Log Data Table */}
      <div className="bg-[#161b22] border border-[#21262d] rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#0d1117] text-[#8b949e] uppercase text-[10px] tracking-wider border-b border-[#21262d]">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Client IP</th>
                <th className="py-2.5 px-3">Event / Action</th>
                <th className="py-2.5 px-3">Sanitized Content</th>
                <th className="py-2.5 px-3">WORM SHA-256 Hash</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#21262d] text-[#c9d1d9]">
              {!result || result.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#6e7681] font-sans">
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
                      className="hover:bg-[#21262d]/50 transition-colors group cursor-pointer"
                      onClick={() => setSelectedEntry(entry)}
                    >
                      <td className="py-2 px-3 text-[#8b949e] whitespace-nowrap text-[11px]">
                        {new Date(entry.timestampUtc).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-semibold border ${
                            isCritical
                              ? 'bg-[#3c1e1e] text-[#f85149] border-[#f85149]/40'
                              : isWarning
                              ? 'bg-[#2b220c] text-[#d29922] border-[#d29922]/40'
                              : 'bg-[#132a1c] text-[#2ea043] border-[#2ea043]/30'
                          }`}
                        >
                          {entry.severity}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-[#58a6ff] font-medium whitespace-nowrap text-[11px]">
                        {entry.clientIp}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="text-[#f0f6fc] font-medium text-[11px]">{entry.eventName}</span>
                        {entry.requestPath && (
                          <span className="text-[#8b949e] text-[10px] block">{entry.httpMethod} {entry.requestPath}</span>
                        )}
                      </td>
                      <td className="py-2 px-3 max-w-xs truncate text-[#8b949e] text-[11px]">
                        {entry.payloadSanitized}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] text-[#6e7681] truncate max-w-[130px]">
                            {entry.tamperProofHash || 'SHA-256 PENDING'}
                          </span>
                          {entry.tamperProofHash && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(entry.tamperProofHash);
                              }}
                              className="text-[#6e7681] hover:text-[#58a6ff] p-0.5"
                              title="คัดลอกแฮชพยานหลักฐาน"
                            >
                              {isCopied ? <Check className="w-3 h-3 text-[#2ea043]" /> : <Copy className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEntry(entry);
                          }}
                          className="px-2 py-0.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] text-[10px] transition-colors cursor-pointer"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75">
          <div className="bg-[#161b22] border border-[#30363d] rounded w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden font-mono">
            <div className="flex items-center justify-between p-4 border-b border-[#21262d] bg-[#0d1117]">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#2ea043]" />
                <h3 className="text-xs font-bold text-[#f0f6fc]">
                  รายละเอียดพยานหลักฐานทางนิติวิทยาศาสตร์ดิจิทัล (Log Inspection)
                </h3>
              </div>
              <button
                onClick={() => setSelectedEntry(null)}
                className="text-[#8b949e] hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 bg-[#0d1117] p-3 rounded border border-[#21262d] text-[11px]">
                <div>
                  <span className="text-[#6e7681] block">Log ID:</span>
                  <span className="text-[#f0f6fc] font-bold">{selectedEntry.logId}</span>
                </div>
                <div>
                  <span className="text-[#6e7681] block">Timestamp (NTP Stratum 1 Synchronized):</span>
                  <span className="text-[#2ea043]">{selectedEntry.timestampUtc}</span>
                </div>
                <div>
                  <span className="text-[#6e7681] block">Client IP (Sec 26 Custody):</span>
                  <span className="text-[#58a6ff] font-bold">{selectedEntry.clientIp}</span>
                </div>
                <div>
                  <span className="text-[#6e7681] block">Severity & Category:</span>
                  <span className="text-[#f85149] font-bold">{selectedEntry.severity} (Cat: {selectedEntry.category})</span>
                </div>
              </div>

              <div>
                <span className="text-[#8b949e] font-semibold block mb-1 text-[11px]">Cryptographic Chain of Custody:</span>
                <div className="bg-[#0d1117] p-2.5 rounded border border-[#21262d] space-y-1 text-[10px]">
                  <div><strong className="text-[#6e7681]">TamperProof Hash:</strong> <span className="text-[#58a6ff]">{selectedEntry.tamperProofHash}</span></div>
                  <div><strong className="text-[#6e7681]">Merkle Root:</strong> <span className="text-[#8b949e]">{selectedEntry.merkleRoot}</span></div>
                  <div><strong className="text-[#6e7681]">Previous Entry Hash:</strong> <span className="text-[#6e7681]">{selectedEntry.previousEntryHash}</span></div>
                </div>
              </div>

              <div>
                <span className="text-[#8b949e] font-semibold block mb-1 text-[11px]">Sanitized Payload (PII Redacted: {selectedEntry.piiRedactedCount}):</span>
                <pre className="bg-[#0d1117] p-2.5 rounded border border-[#21262d] text-[#c9d1d9] overflow-x-auto text-[10px] whitespace-pre-wrap">
                  {selectedEntry.payloadSanitized}
                </pre>
              </div>

              <div>
                <span className="text-[#8b949e] font-semibold block mb-1 text-[11px]">Full Technical JSON:</span>
                <pre className="bg-[#0d1117] p-2.5 rounded border border-[#21262d] text-[#8b949e] overflow-x-auto text-[10px]">
                  {JSON.stringify(selectedEntry, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-3 border-t border-[#21262d] bg-[#0d1117] flex justify-end">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-3 py-1.5 rounded bg-[#21262d] text-[#c9d1d9] hover:text-white text-xs cursor-pointer font-medium"
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
