// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState } from 'react';
import { Network, RotateCcw, Crosshair, ShieldCheck, Terminal, X } from 'lucide-react';
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
    if (risk === 'Critical' || type === 'AttackerIp') return '#f85149';
    if (type === 'MitreTechnique') return '#d29922';
    if (type === 'TargetAsset') return '#58a6ff';
    return '#2ea043';
  };

  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded p-4 flex flex-col h-[500px] relative">
      {/* Header bar */}
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-[#21262d] flex items-center justify-center text-[#58a6ff]">
            <Network className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-[#f0f6fc] uppercase tracking-wider font-mono">
              {t.graphTitle}
            </h3>
            <p className="text-[10px] text-[#8b949e] font-mono">
              GRAPH-NEURAL CORRELATION // LIVE ATTACK TRAJECTORIES
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              className="px-2.5 py-1 rounded bg-[#21262d] text-[#c9d1d9] hover:text-white border border-[#30363d] text-xs font-mono flex items-center gap-1.5 cursor-pointer transition-colors"
            >
              <RotateCcw className="w-3 h-3 text-[#58a6ff]" />
              <span>{lang === 'th' ? 'รีเฟรชกราฟ' : 'Refresh'}</span>
            </button>
          )}
        </div>
      </div>

      {/* SVG Canvas Map */}
      <div className="flex-grow relative overflow-hidden bg-[#0d1117] rounded border border-[#21262d]">
        <svg className="w-full h-full min-h-[400px]" viewBox="0 0 780 420" preserveAspectRatio="xMidYMid meet">
          <defs>
            <marker
              id="arrow-crit"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#f85149" />
            </marker>
            <marker
              id="arrow-norm"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#30363d" />
            </marker>
          </defs>

          {/* Render Vector Edges */}
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
                  stroke={isCrit ? '#f85149' : '#30363d'}
                  strokeWidth={isCrit ? '1.5' : '1'}
                  strokeOpacity={isCrit ? '0.8' : '0.6'}
                  markerEnd={isCrit ? 'url(#arrow-crit)' : 'url(#arrow-norm)'}
                />

                {/* Packet Particle */}
                <circle r={isCrit ? '2.5' : '2'} fill={isCrit ? '#f85149' : '#58a6ff'}>
                  <animate
                    attributeName="cx"
                    from={sourcePos.x}
                    to={targetPos.x}
                    dur={`${2.5 + (idx % 2)}s`}
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="cy"
                    from={sourcePos.y}
                    to={targetPos.y}
                    dur={`${2.5 + (idx % 2)}s`}
                    repeatCount="indefinite"
                  />
                </circle>

                {/* Edge Relation Label */}
                <text
                  x={(sourcePos.x + targetPos.x) / 2}
                  y={(sourcePos.y + targetPos.y) / 2 - 6}
                  fill={isCrit ? '#f85149' : '#8b949e'}
                  fontSize="8.5"
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
                className="cursor-pointer"
              >
                {/* Node Body */}
                <rect
                  x="-18"
                  y="-18"
                  width="36"
                  height="36"
                  rx="4"
                  fill="#161b22"
                  stroke={isSelected ? '#58a6ff' : color}
                  strokeWidth={isSelected ? '2' : '1'}
                />

                {/* Status Dot */}
                <circle cx="0" cy="0" r="4" fill={color} />

                {/* Node Label */}
                <text
                  y="28"
                  fill="#f0f6fc"
                  fontSize="9.5"
                  fontWeight="600"
                  textAnchor="middle"
                  fontFamily="JetBrains Mono, monospace"
                  className="select-none"
                >
                  {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                </text>

                {/* Risk Micro-Pill */}
                <text
                  y="39"
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
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-80 bg-[#161b22] border border-[#30363d] rounded p-3 font-mono text-xs z-20">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#21262d]">
              <div className="flex items-center gap-1.5">
                <Crosshair className="w-3.5 h-3.5 text-[#58a6ff]" />
                <span className="font-bold text-[#f0f6fc] text-xs truncate max-w-[180px]">
                  {selectedNode.label}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-[#8b949e] hover:text-white p-0.5 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-1.5 text-[#c9d1d9] text-[11px]">
              <div className="flex justify-between items-center">
                <span className="text-[#8b949e]">Topology Type:</span>
                <span className="text-[#58a6ff] font-semibold">
                  {selectedNode.type}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#8b949e]">Risk Score:</span>
                <span className="text-[#f85149] font-bold">
                  {selectedNode.value} / 100 ({selectedNode.riskLevel})
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[#8b949e]">Mitigation:</span>
                <span className="text-[#2ea043] font-semibold">
                  Zero-Trust Quarantined
                </span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-[#21262d] space-y-1.5">
              {investigatingMsg && (
                <div className="p-1.5 rounded bg-[#132a1c] border border-[#2ea043]/30 text-[#2ea043] text-[10px] font-mono flex items-center gap-1.5">
                  <ShieldCheck className="w-3 h-3 text-[#2ea043] shrink-0" />
                  <span>{investigatingMsg}</span>
                </div>
              )}
              <button
                type="button"
                onClick={() => {
                  setInvestigatingMsg(
                    lang === 'th'
                      ? `เปิดท่อดักพยานหลักฐาน: ${selectedNode.label}`
                      : `Forensic capture engaged: ${selectedNode.label}`
                  );
                }}
                className="w-full py-1 px-2 rounded bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] text-[11px] font-semibold border border-[#30363d] text-center cursor-pointer transition-colors flex items-center justify-center gap-1.5"
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
