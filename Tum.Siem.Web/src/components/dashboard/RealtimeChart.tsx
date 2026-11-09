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
    const height = (canvas.height = 180);

    ctx.clearRect(0, 0, width, height);

    // 1. Draw Oscilloscope Grid Lines (Hairline)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
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
    ctx.setLineDash([3, 3]);
    ctx.strokeStyle = 'rgba(248, 81, 73, 0.4)';
    ctx.lineWidth = 1;
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(width, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Add threshold label
    ctx.fillStyle = 'rgba(248, 81, 73, 0.7)';
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.fillText('CRITICAL ALERT THRESHOLD (70)', width - 180, thresholdY - 4);

    if (dataPoints.length < 2) return;

    const step = width / (dataPoints.length - 1);

    // 3. Draw Clean Area
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    if (isHighRisk) {
      gradient.addColorStop(0, 'rgba(248, 81, 73, 0.15)');
      gradient.addColorStop(1, 'rgba(248, 81, 73, 0.0)');
    } else {
      gradient.addColorStop(0, 'rgba(31, 111, 235, 0.15)');
      gradient.addColorStop(1, 'rgba(31, 111, 235, 0.0)');
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

    // 4. Draw Crisp Line Stroke (No neon blur)
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

    ctx.strokeStyle = isHighRisk ? '#f85149' : '#388bfd';
    ctx.lineWidth = 1.75;
    ctx.stroke();

    // 5. Draw Marker on Latest Value
    const lastIdx = dataPoints.length - 1;
    const lastX = lastIdx * step;
    const lastNormalized = Math.min(100, Math.max(0, dataPoints[lastIdx]));
    const lastY = height - (lastNormalized / 100) * (height - 30) - 15;

    ctx.beginPath();
    ctx.arc(lastX, lastY, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = isHighRisk ? '#f85149' : '#388bfd';
    ctx.fill();
  }, [dataPoints, isHighRisk]);

  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded p-4 mb-4 relative">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
            <TrendingUp className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-[#f0f6fc] uppercase tracking-wider font-mono">
              {t.chartTitle}
            </h3>
            <p className="text-[10px] text-[#8b949e] font-mono">
              ALGORITHMIC MULTI-FACTOR EVALUATOR // REAL-TIME SAMPLING
            </p>
          </div>
        </div>

        {/* Live Risk Posture Badge */}
        <div className="flex items-center gap-2">
          <div
            className={`px-2.5 py-0.5 rounded border flex items-center gap-1.5 font-mono text-[11px] ${
              isHighRisk
                ? 'bg-[#3c1e1e] border-[#f85149]/40 text-[#f85149]'
                : isMediumRisk
                ? 'bg-[#2b220c] border-[#d29922]/40 text-[#d29922]'
                : 'bg-[#132a1c] border-[#2ea043]/40 text-[#2ea043]'
            }`}
          >
            {isHighRisk ? (
              <AlertTriangle className="w-3 h-3 text-[#f85149]" />
            ) : (
              <ShieldCheck className="w-3 h-3 text-[#2ea043]" />
            )}
            <span className="font-semibold">
              {lang === 'th' ? 'ระดับภัยคุกคาม:' : 'POSTURE:'}{' '}
              {isHighRisk ? 'CRITICAL' : isMediumRisk ? 'ELEVATED' : 'NOMINAL'}
            </span>
            <span className="font-bold px-1 rounded bg-black/40 text-[#f0f6fc] font-tabular">
              {currentScore.toFixed(0)} / 100
            </span>
          </div>

          <div className="hidden sm:flex items-center gap-1 text-[10px] text-[#6e7681] font-mono">
            <Activity className="w-3 h-3 text-[#58a6ff]" />
            <span>1s INTERVAL</span>
          </div>
        </div>
      </div>

      {/* Realtime Canvas */}
      <div className="w-full h-[180px] relative">
        <canvas ref={canvasRef} className="w-full h-full block" />
      </div>
    </div>
  );
};
