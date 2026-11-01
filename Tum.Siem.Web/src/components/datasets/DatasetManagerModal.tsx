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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
      <div className="bg-[#0B0E1A] border border-cyan-500/40 rounded-3xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-[0_0_50px_rgba(56,189,248,0.2)] overflow-hidden font-sans">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/10 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center text-cyan-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">
                {t.datasetModalTitle}
              </h3>
              <p className="text-xs text-slate-400 font-normal">
                {t.datasetModalDesc}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1.5 rounded-lg bg-slate-800/80 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Datasets Catalog List */}
        <div className="p-6 overflow-y-auto space-y-4 flex-grow text-xs">
          {/* Error Banner */}
          {modalError && (
            <div className="p-4 rounded-2xl border border-rose-500/40 bg-rose-950/40 text-rose-300 text-xs font-mono flex items-center justify-between gap-3 animate-fadeIn">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400" />
                <p className="font-bold">{modalError}</p>
              </div>
              <button
                type="button"
                onClick={() => setModalError(null)}
                className="text-rose-400 hover:text-white p-1 rounded-lg bg-rose-900/40 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Success Banner */}
          {lastResult && (
            <div
              className={`p-4 rounded-2xl border text-xs font-mono flex items-start gap-3 ${
                lastResult.success
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}
            >
              <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
              <div>
                <p className="font-bold">{lastResult.message}</p>
                {lastResult.ingestedCount > 0 && (
                  <div className="mt-1 space-y-0.5 text-[11px] text-slate-300">
                    <div>• Ingested Events: {lastResult.ingestedCount}</div>
                    <div>• Sigma Matched Threats: {lastResult.threatMatchesCount}</div>
                    <div>• Merkle Root: {lastResult.globalMerkleRoot}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Catalog Items */}
          <div className="space-y-3 font-mono">
            {catalog?.datasets.map((item) => {
              const isLoading = loadingId === item.id;
              return (
                <div
                  key={item.id}
                  className="bg-slate-900/60 border border-white/5 rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-cyan-500/30 transition-all"
                >
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-bold text-white text-sm font-sans">{item.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        {item.category}
                      </span>
                      <span className="text-[10px] text-slate-500 font-normal">
                        ({item.recordCount} {t.records})
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 font-sans leading-relaxed">
                      {item.description}
                    </p>

                    <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
                      <span>Source: <strong className="text-slate-400">{item.source}</strong></span>
                      <span>• MITRE: <strong className="text-cyan-400">{item.mitreTechniques.join(', ')}</strong></span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleLoad(item.id)}
                    disabled={isLoading}
                    className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shrink-0 flex items-center justify-center gap-1.5 transition-all shadow-[0_0_15px_rgba(56,189,248,0.25)] cursor-pointer disabled:opacity-50"
                  >
                    <Play className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : 'fill-current'}`} />
                    <span>{isLoading ? t.btnLoadingDataset : t.btnLoadDataset}</span>
                  </button>
                </div>
              );
            })}
          </div>

          {/* Quick Load All Button */}
          <div className="flex justify-end pt-2">
            <button
              onClick={() => handleLoad('all')}
              disabled={loadingId === 'all'}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 text-slate-950 font-bold text-xs shadow-lg flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Database className="w-4 h-4" />
              <span>{loadingId === 'all' ? t.btnLoadingDataset : 'โหลดชุดข้อมูลภัยคุกคามจริงทั้งหมด (Ingest All Real Datasets)'}</span>
            </button>
          </div>
        </div>

        {/* Modal Footer: Production Clean Reset */}
        <div className="p-5 border-t border-white/10 bg-slate-900/90 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-rose-400 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span className="font-sans text-[11px] text-slate-400">
              {confirmPurge ? t.purgeConfirm : 'ล้างข้อมูลทดสอบทั้งหมดก่อนติดตั้งให้ลูกค้า (Production Clean State)'}
            </span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {confirmPurge && (
              <button
                onClick={() => setConfirmPurge(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:text-white text-xs cursor-pointer"
              >
                ยกเลิก
              </button>
            )}
            <button
              onClick={handlePurge}
              disabled={isPurging}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer ${
                confirmPurge
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-[0_0_15px_rgba(244,63,94,0.4)]'
                  : 'bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-500/40'
              }`}
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{confirmPurge ? 'ยืนยันการล้างข้อมูลทั้งหมด' : t.btnPurgeProd}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
