// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect } from 'react';
import { Database, Trash2, CheckCircle2, AlertTriangle, Play, X } from 'lucide-react';
import { siemApi } from '../../api/siemApi';
import type { DatasetCatalogResponse, DatasetOperationResult } from '../../types/auth';
import { translations, type Language } from '../../i18n/translations';

interface DatasetManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDatasetChanged: () => void;
  lang: Language;
}

export const DatasetManagerModal: React.FC<DatasetManagerModalProps> = ({
  isOpen,
  onClose,
  onDatasetChanged,
  lang,
}) => {
  const [catalog, setCatalog] = useState<DatasetCatalogResponse | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<DatasetOperationResult | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);
  const [isPurging, setIsPurging] = useState<boolean>(false);
  const [confirmPurge, setConfirmPurge] = useState<boolean>(false);

  const t = translations[lang];

  useEffect(() => {
    if (isOpen) {
      setModalError(null);
      siemApi.getDatasetCatalog().then(setCatalog).catch(console.error);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleLoad = async (datasetId: string) => {
    setLoadingId(datasetId);
    setLastResult(null);
    setModalError(null);
    try {
      const res = await siemApi.loadDataset(datasetId, 50);
      setLastResult(res);
      onDatasetChanged();
    } catch (err: any) {
      setModalError(err.message || 'Error loading dataset');
    } finally {
      setLoadingId(null);
    }
  };

  const handlePurge = async () => {
    if (!confirmPurge) {
      setConfirmPurge(true);
      return;
    }

    setIsPurging(true);
    setLastResult(null);
    setModalError(null);
    try {
      const res = await siemApi.purgeDataForProduction();
      setLastResult(res);
      setConfirmPurge(false);
      onDatasetChanged();
    } catch (err: any) {
      setModalError(err.message || 'Error purging data');
    } finally {
      setIsPurging(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75">
      <div className="bg-[#161b22] border border-[#30363d] rounded w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden font-sans">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#21262d] bg-[#0d1117]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-[#f0f6fc]">
                {t.datasetModalTitle}
              </h3>
              <p className="text-[11px] text-[#8b949e]">
                {t.datasetModalDesc}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#8b949e] hover:text-white p-1 rounded bg-[#21262d] border border-[#30363d] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Datasets Catalog List */}
        <div className="p-4 overflow-y-auto space-y-3 flex-grow text-xs">
          {/* Error Banner */}
          {modalError && (
            <div className="p-3 rounded border border-[#f85149]/40 bg-[#3c1e1e] text-[#f85149] text-xs font-mono flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-[#f85149]" />
                <p className="font-semibold">{modalError}</p>
              </div>
              <button
                type="button"
                onClick={() => setModalError(null)}
                className="text-[#f85149] hover:text-white p-0.5 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Success Banner */}
          {lastResult && (
            <div
              className={`p-3 rounded border text-xs font-mono flex items-start gap-2 ${
                lastResult.success
                  ? 'bg-[#132a1c] border-[#2ea043]/30 text-[#2ea043]'
                  : 'bg-[#3c1e1e] border-[#f85149]/40 text-[#f85149]'
              }`}
            >
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-[#2ea043]" />
              <div>
                <p className="font-bold">{lastResult.message}</p>
                {lastResult.ingestedCount > 0 && (
                  <div className="mt-1 space-y-0.5 text-[10px] text-[#8b949e]">
                    <div>• Ingested Events: {lastResult.ingestedCount}</div>
                    <div>• Sigma Matched Threats: {lastResult.threatMatchesCount}</div>
                    <div>• Merkle Root: {lastResult.globalMerkleRoot}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Catalog Items */}
          <div className="space-y-2 font-mono">
            {catalog?.datasets.map((item) => {
              const isLoading = loadingId === item.id;
              return (
                <div
                  key={item.id}
                  className="bg-[#0d1117] border border-[#21262d] rounded p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-[#30363d] transition-colors"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-[#f0f6fc] text-xs font-sans">{item.name}</span>
                      <span className="px-1.5 py-0.2 rounded text-[9px] bg-[#162a3a] text-[#58a6ff] border border-[#58a6ff]/30">
                        {item.category}
                      </span>
                      <span className="text-[10px] text-[#6e7681]">
                        ({item.recordCount} {t.records})
                      </span>
                    </div>

                    <p className="text-[11px] text-[#8b949e] font-sans leading-relaxed">
                      {item.description}
                    </p>

                    <div className="flex flex-wrap items-center gap-2 text-[10px] text-[#6e7681]">
                      <span>Source: <strong className="text-[#8b949e]">{item.source}</strong></span>
                      <span>• MITRE: <strong className="text-[#58a6ff]">{item.mitreTechniques.join(', ')}</strong></span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleLoad(item.id)}
                    disabled={isLoading}
                    className="px-3 py-1.5 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white font-medium text-xs shrink-0 flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <Play className={`w-3 h-3 ${isLoading ? 'animate-spin' : 'fill-current'}`} />
                    <span>{isLoading ? t.btnLoadingDataset : t.btnLoadDataset}</span>
                  </button>
                </div>
              );
            })}
          </div>

          {/* Quick Load All Button */}
          <div className="flex justify-end pt-1">
            <button
              onClick={() => handleLoad('all')}
              disabled={loadingId === 'all'}
              className="px-3.5 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#c9d1d9] font-medium text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors"
            >
              <Database className="w-3.5 h-3.5 text-[#58a6ff]" />
              <span>{loadingId === 'all' ? t.btnLoadingDataset : 'โหลดชุดข้อมูลภัยคุกคามจริงทั้งหมด (Ingest All Real Datasets)'}</span>
            </button>
          </div>
        </div>

        {/* Modal Footer: Production Clean Reset */}
        <div className="p-3 border-t border-[#21262d] bg-[#0d1117] flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[#f85149] text-xs font-mono">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span className="font-sans text-[11px] text-[#8b949e]">
              {confirmPurge ? t.purgeConfirm : 'ล้างข้อมูลทดสอบทั้งหมดก่อนติดตั้งให้ลูกค้า (Production Clean State)'}
            </span>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {confirmPurge && (
              <button
                onClick={() => setConfirmPurge(false)}
                className="px-3 py-1.5 rounded bg-[#21262d] text-[#c9d1d9] hover:text-white text-xs cursor-pointer border border-[#30363d]"
              >
                ยกเลิก
              </button>
            )}
            <button
              onClick={handlePurge}
              disabled={isPurging}
              className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                confirmPurge
                  ? 'bg-[#f85149] text-white hover:bg-[#da3633]'
                  : 'bg-[#3c1e1e] hover:bg-[#4d2525] text-[#f85149] border border-[#f85149]/40'
              }`}
            >
              <Trash2 className="w-3 h-3" />
              <span>{confirmPurge ? 'ยืนยันการล้างข้อมูลทั้งหมด' : t.btnPurgeProd}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
