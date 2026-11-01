// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState } from 'react';
import { Network, RotateCcw, ShieldAlert, Crosshair, ShieldCheck, Terminal, X } from 'lucide-react';
import type { AttackGraphData, AttackGraphNode } from '../../types/siem';
import { translations, type Language } from '../../i18n/translations';

interface AttackGraphViewProps {
  data: AttackGraphData | null;
  onRefresh?: () => void;
  lang?: Language;
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({ data, onRefresh, lang = 'th' }) => {
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null);
  const [investigatingMsg, setInvestigatingMsg] = useState<string | null>(null);
  const t = translations[lang];

  // Default rich topology nodes
  const defaultNodes: AttackGraphNode[] = [
    { id: 'att-1', label: '185.220.101.5 (Tor Exit)', type: 'AttackerIp', riskLevel: 'Critical', value: 95 },
    { id: 'att-2', label: '45.33.32.156 (AI Scanner)', type: 'AttackerIp', riskLevel: 'Critical', value: 92 },
    { id: 'tech-1', label: 'T1190: Exploit Public App', type: 'MitreTechnique', riskLevel: 'High', value: 85 },
    { id: 'tech-2', label: 'T1059: Command Scripting', type: 'MitreTechnique', riskLevel: 'High', value: 80 },
    { id: 'asset-1', label: 'Core Banking API (/login)', type: 'TargetAsset', riskLevel: 'High', value: 75 },
    { id: 'asset-2', label: 'Agentic Tool Bridge (/mcp)', type: 'TargetAsset', riskLevel: 'High', value: 88 },
    { id: 'core-1', label: 'TUM Sovereign Quantum Core', type: 'Application', riskLevel: 'Low', value: 10 },
  ];

  const defaultEdges = [
    { source: 'att-1', target: 'tech-1', relation: 'Executes SQLi', severity: 'Critical' },
    { source: 'tech-1', target: 'asset-1', relation: 'Targets API', severity: 'Critical' },
    { source: 'att-2', target: 'tech-2', relation: 'Injects Prompt', severity: 'Critical' },
    { source: 'tech-2', target: 'asset-2', relation: 'Hijacks MCP', severity: 'High' },
    { source: 'asset-1', target: 'core-1', relation: 'Auto-Blocked (0.11ms)', severity: 'Low' },
    { source: 'asset-2', target: 'core-1', relation: 'Sandboxed (0.14ms)', severity: 'Low' },
  ];

  const nodes = data && data.nodes && data.nodes.length > 0 ? data.nodes : defaultNodes;
  const edges = data && data.edges && data.edges.length > 0 ? data.edges : defaultEdges;

  // Node coordinates for tactical map layout
  const positions: Record<string, { x: number; y: number }> = {
    'att-1': { x: 100, y: 110 },
    'att-2': { x: 100, y: 310 },
    'tech-1': { x: 300, y: 130 },
    'tech-2': { x: 300, y: 290 },
    'asset-1': { x: 500, y: 120 },
    'asset-2': { x: 500, y: 300 },
    'core-1': { x: 690, y: 210 },
  };

  const getNodePos = (id: string, index: number) => {
    if (positions[id]) return positions[id];
    const angle = (index / nodes.length) * 2 * Math.PI;
    return {
      x: 390 + 240 * Math.cos(angle),
      y: 210 + 130 * Math.sin(angle),
    };
  };

  const getNodeColor = (type: string, risk: string) => {
    if (risk === 'Critical' || type === 'AttackerIp') return '#F43F5E';
    if (type === 'MitreTechnique') return '#F59E0B';
    if (type === 'TargetAsset') return '#38BDF8';
    return '#10B981';
  };

  return (
    <div className="bg-[#0b101e]/80 border border-white/10 rounded-2xl p-5 backdrop-blur-xl flex flex-col h-[530px] relative overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              {t.graphTitle}
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              GRAPH-NEURAL CORRELATION // LIVE ATTACK TRAJECTORIES
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              className="px-3 py-1.5 rounded-xl bg-slate-900/90 text-slate-300 hover:text-white border border-white/10 text-xs font-mono flex items-center gap-1.5 cursor-pointer hover:border-cyan-500/40 transition-all"
            >
              <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
              <span>{lang === 'th' ? 'รีเฟรชกราฟ' : 'Refresh'}</span>
            </button>
          )}
        </div>
      </div>

      {/* SVG Canvas Map */}
      <div className="flex-grow relative overflow-hidden bg-[#060a14] rounded-xl border border-white/5 cyber-grid">
        {/* Background Radar Rings */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 border border-cyan-500/10 rounded-full pointer-events-none" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 border border-indigo-500/10 rounded-full pointer-events-none" />

        <svg className="w-full h-full min-h-[420px]" viewBox="0 0 780 420" preserveAspectRatio="xMidYMid meet">
          <defs>
            <marker
              id="arrow-crit"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#F43F5E" />
            </marker>
            <marker
              id="arrow-norm"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#818CF8" />
            </marker>
          </defs>

          {/* Render Vector Edges with Particle Simulation */}
          {edges.map((edge, idx) => {
            const sIdx = nodes.findIndex((n) => n.id === edge.source);
            const tIdx = nodes.findIndex((n) => n.id === edge.target);
            const sourcePos = getNodePos(edge.source, sIdx >= 0 ? sIdx : 0);
            const targetPos = getNodePos(edge.target, tIdx >= 0 ? tIdx : 1);
            const isCrit = edge.severity === 'Critical';

            return (
              <g key={`edge-${idx}`}>
                {/* Edge line */}
                <line
                  x1={sourcePos.x}
                  y1={sourcePos.y}
                  x2={targetPos.x}
                  y2={targetPos.y}
                  stroke={isCrit ? '#F43F5E' : '#818CF8'}
                  strokeWidth={isCrit ? '2' : '1.5'}
                  strokeOpacity="0.7"
                  markerEnd={isCrit ? 'url(#arrow-crit)' : 'url(#arrow-norm)'}
                />

                {/* Animated Packet Particle traveling along the edge */}
                <circle r={isCrit ? '3' : '2'} fill={isCrit ? '#FDA4AF' : '#A5B4FC'}>
                  <animate
                    attributeName="cx"
                    from={sourcePos.x}
                    to={targetPos.x}
                    dur={`${2 + (idx % 3)}s`}
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="cy"
                    from={sourcePos.y}
                    to={targetPos.y}
                    dur={`${2 + (idx % 3)}s`}
                    repeatCount="indefinite"
                  />
                </circle>

                {/* Edge Relation Label */}
                <text
                  x={(sourcePos.x + targetPos.x) / 2}
                  y={(sourcePos.y + targetPos.y) / 2 - 8}
                  fill={isCrit ? '#FDA4AF' : '#94A3B8'}
                  fontSize="9"
                  fontFamily="JetBrains Mono, monospace"
                  textAnchor="middle"
                  className="select-none pointer-events-none"
                >
                  {edge.relation}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((node, idx) => {
            const pos = getNodePos(node.id, idx);
            const color = getNodeColor(node.type, node.riskLevel);
            const isSelected = selectedNode?.id === node.id;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer transition-transform duration-200 hover:scale-105"
              >
                {/* Outer Glow Halo */}
                <circle
                  r={isSelected ? 26 : 21}
                  fill="#0B0F19"
                  stroke={color}
                  strokeWidth={isSelected ? '3.5' : '2'}
                  filter={isSelected ? `drop-shadow(0px 0px 10px ${color})` : undefined}
                />
                {/* Inner Core */}
                <circle r="6" fill={color} className="animate-pulse" />

                {/* Node Label */}
                <text
                  y="34"
                  fill="#F8FAFC"
                  fontSize="10"
                  fontWeight="bold"
                  textAnchor="middle"
                  fontFamily="JetBrains Mono, monospace"
                  className="select-none"
                >
                  {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                </text>

                {/* Risk Micro-Pill */}
                <text
                  y="46"
                  fill={color}
                  fontSize="8"
                  textAnchor="middle"
                  fontFamily="JetBrains Mono, monospace"
                  className="select-none"
                >
                  [{node.value}/100 {node.riskLevel.toUpperCase()}]
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Tactical Details Drawer */}
        {selectedNode && (
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-88 bg-[#090e1c]/95 border border-cyan-500/40 rounded-2xl p-4 backdrop-blur-xl shadow-2xl font-mono text-xs z-20">
            <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-white text-sm truncate max-w-[200px]">
                  {selectedNode.label}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between items-center">
                <span className="text-slate-500">Topology Type:</span>
                <span className="text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30">
                  {selectedNode.type}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500">Risk Assessment:</span>
                <span className="text-rose-400 font-bold flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  {selectedNode.value} / 100 ({selectedNode.riskLevel})
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500">Active Defense:</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Zero-Trust Quarantined
                </span>
              </div>
            </div>

            <div className="mt-3 pt-2.5 border-t border-white/5 space-y-2">
              {investigatingMsg && (
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[11px] font-mono flex items-center gap-1.5 animate-fadeIn">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>{investigatingMsg}</span>
                </div>
              )}
              <button
                type="button"
                onClick={() => {
                  setInvestigatingMsg(
                    lang === 'th'
                      ? `เปิดท่อดักพยานหลักฐานสำหรับ: ${selectedNode.label} สำเร็จ`
                      : `Forensic capture pipeline engaged for: ${selectedNode.label}`
                  );
                }}
                className="w-full py-1.5 px-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[11px] font-bold border border-cyan-500/40 text-center cursor-pointer transition-all flex items-center justify-center gap-1.5"
              >
                <Terminal className="w-3 h-3" />
                {lang === 'th' ? 'สืบค้นพยานหลักฐานเชิงลึก' : 'Deep Forensic Pipeline'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
