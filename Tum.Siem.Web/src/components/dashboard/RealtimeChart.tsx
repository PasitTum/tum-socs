// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useEffect, useRef } from 'react';
import { TrendingUp, Activity, AlertTriangle, ShieldCheck } from 'lucide-react';
import { translations, type Language } from '../../i18n/translations';

interface RealtimeChartProps {
  dataPoints: number[];
  lang?: Language;
}

export const RealtimeChart: React.FC<RealtimeChartProps> = ({ dataPoints, lang = 'th' }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const t = translations[lang];

  const currentScore = dataPoints.length > 0 ? dataPoints[dataPoints.length - 1] : 20;
  const isHighRisk = currentScore >= 70;
  const isMediumRisk = currentScore >= 40 && currentScore < 70;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = (canvas.width = canvas.parentElement?.clientWidth || 700);
    const height = (canvas.height = 190);

    ctx.clearRect(0, 0, width, height);

    // 1. Draw Tactical Oscilloscope Grid Lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    for (let y = 30; y < height; y += 35) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }
    for (let x = 40; x < width; x += 60) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }

    // 2. Draw Threshold Danger Line (Score = 70)
    const thresholdY = height - (70 / 100) * (height - 30) - 15;
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = 'rgba(244, 63, 94, 0.35)';
    ctx.lineWidth = 1.5;
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(width, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]); // Reset line dash

    // Add threshold label
    ctx.fillStyle = 'rgba(244, 63, 94, 0.6)';
    ctx.font = '9px JetBrains Mono, monospace';
    ctx.fillText('CRITICAL ALERT THRESHOLD (70)', width - 180, thresholdY - 4);

    if (dataPoints.length < 2) return;

    const step = width / (dataPoints.length - 1);

    // 3. Draw Gradient Wave Area
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    if (isHighRisk) {
      gradient.addColorStop(0, 'rgba(244, 63, 94, 0.35)');
      gradient.addColorStop(1, 'rgba(244, 63, 94, 0.0)');
    } else {
      gradient.addColorStop(0, 'rgba(56, 189, 248, 0.3)');
      gradient.addColorStop(0.5, 'rgba(99, 102, 241, 0.1)');
      gradient.addColorStop(1, 'rgba(56, 189, 248, 0.0)');
    }

    ctx.beginPath();
    ctx.moveTo(0, height);

    dataPoints.forEach((val, idx) => {
      const x = idx * step;
      const normalized = Math.min(100, Math.max(0, val));
      const y = height - (normalized / 100) * (height - 30) - 15;
      if (idx === 0) {
        ctx.lineTo(x, y);
      } else {
        const prevX = (idx - 1) * step;
        const prevNormalized = Math.min(100, Math.max(0, dataPoints[idx - 1]));
        const prevY = height - (prevNormalized / 100) * (height - 30) - 15;
        const cpX = (prevX + x) / 2;
        ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
      }
    });

    ctx.lineTo(width, height);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // 4. Draw Glowing Neon Stroke
    ctx.beginPath();
    dataPoints.forEach((val, idx) => {
      const x = idx * step;
      const normalized = Math.min(100, Math.max(0, val));
      const y = height - (normalized / 100) * (height - 30) - 15;
      if (idx === 0) {
        ctx.moveTo(x, y);
      } else {
        const prevX = (idx - 1) * step;
        const prevNormalized = Math.min(100, Math.max(0, dataPoints[idx - 1]));
        const prevY = height - (prevNormalized / 100) * (height - 30) - 15;
        const cpX = (prevX + x) / 2;
        ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
      }
    });

    ctx.strokeStyle = isHighRisk ? '#F43F5E' : '#38BDF8';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = isHighRisk ? 'rgba(244, 63, 94, 0.9)' : 'rgba(56, 189, 248, 0.9)';
    ctx.shadowBlur = 12;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // 5. Draw Pulse Marker on the Latest Value
    const lastIdx = dataPoints.length - 1;
    const lastX = lastIdx * step;
    const lastNormalized = Math.min(100, Math.max(0, dataPoints[lastIdx]));
    const lastY = height - (lastNormalized / 100) * (height - 30) - 15;

    ctx.beginPath();
    ctx.arc(lastX, lastY, 5, 0, Math.PI * 2);
    ctx.fillStyle = isHighRisk ? '#F43F5E' : '#38BDF8';
    ctx.fill();

    ctx.beginPath();
    ctx.arc(lastX, lastY, 9, 0, Math.PI * 2);
    ctx.strokeStyle = isHighRisk ? 'rgba(244, 63, 94, 0.5)' : 'rgba(56, 189, 248, 0.5)';
    ctx.lineWidth = 2;
    ctx.stroke();
  }, [dataPoints, isHighRisk]);

  return (
    <div className="bg-[#0b101e]/80 border border-white/10 rounded-2xl p-5 backdrop-blur-xl mb-6 relative overflow-hidden group shadow-xl">
      {/* Top Header & Tactical Status Callouts */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <TrendingUp className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              {t.chartTitle}
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              ALGORITHMIC MULTI-FACTOR EVALUATOR // REAL-TIME SAMPLING
            </p>
          </div>
        </div>

        {/* Live Risk Posture Badge */}
        <div className="flex items-center gap-3">
          <div
            className={`px-3 py-1 rounded-xl border flex items-center gap-2 font-mono text-xs ${
              isHighRisk
                ? 'bg-rose-950/60 border-rose-500/50 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.3)] animate-pulse'
                : isMediumRisk
                ? 'bg-amber-950/60 border-amber-500/40 text-amber-300'
                : 'bg-emerald-950/60 border-emerald-500/30 text-emerald-300'
            }`}
          >
            {isHighRisk ? (
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span className="font-bold">
              {lang === 'th' ? 'ระดับภัยคุกคาม:' : 'POSTURE:'}{' '}
              {isHighRisk ? 'CRITICAL' : isMediumRisk ? 'ELEVATED' : 'NOMINAL'}
            </span>
            <span className="font-black px-1.5 py-0.5 rounded bg-black/40 text-white font-tabular">
              {currentScore.toFixed(0)} / 100
            </span>
          </div>

          <div className="hidden sm:flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
            <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>1s INTERVAL</span>
          </div>
        </div>
      </div>

      {/* Realtime Canvas */}
      <div className="w-full h-[190px] relative">
        <canvas ref={canvasRef} className="w-full h-full block" />
      </div>
    </div>
  );
};
