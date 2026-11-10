// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect, useCallback } from 'react';
import {
  Boxes,
  Server,
  Layers,
  Cpu,
  HardDrive,
  Network,
  Copy,
  Check,
  Download,
  Terminal,
  Zap,
  Activity,
  Cloud,
  Play,
  Award,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { siemApi } from '../../api/siemApi';
import type {
  ArchitectureTier,
  DeploymentConfig,
  DeploymentBundle,
  GovernorStats,
  HostNodeMetrics,
  CloudScaleResult,
  HostCommandResult,
  LoadTestRunResult,
  InfraReadinessCertificate,
} from '../../types/siem';
import { translations, type Language } from '../../i18n/translations';

interface DeploymentViewProps {
  lang: Language;
}

type SubTab = 'generator' | 'host-orchestrator' | 'load-test';

export const DeploymentView: React.FC<DeploymentViewProps> = ({ lang }) => {
  const t = translations[lang];

  const [activeSubTab, setActiveSubTab] = useState<SubTab>('generator');

  // Generator Config State
  const [config, setConfig] = useState<DeploymentConfig>({
    tier: 3 as ArchitectureTier,
    domainName: 'siem.ocsc.go.th',
    httpPort: 5200,
    syslogUdpPort: 514,
    syslogTcpPort: 514,
    wormRetentionDays: 90,
    clickHousePassword: 'tum_sovereign_2026',
    clickHouseMemoryLimit: '32Gi',
    enableRedpandaQueue: true,
    enableSmartSamplingSurge: true,
    replicaCount: 6,
    storageSizeGb: 500,
    ntpServerHost: 'time.navy.mi.th',
  });

  // Bundle & UI State
  const [bundle, setBundle] = useState<DeploymentBundle | null>(null);
  const [selectedFileIndex, setSelectedFileIndex] = useState<number>(0);
  const [copied, setCopied] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  // Governor State
  const [governorStats, setGovernorStats] = useState<GovernorStats | null>(null);
  const [isTogglingSurge, setIsTogglingSurge] = useState<boolean>(false);

  // Host Telemetry & Orchestrator State
  const [nodes, setNodes] = useState<HostNodeMetrics[]>([]);
  const [k8sReplicas, setK8sReplicas] = useState<number>(6);
  const [awsInstanceType, setAwsInstanceType] = useState<string>('c6i.4xlarge');
  const [awsCount, setAwsCount] = useState<number>(2);
  const [isScaling, setIsScaling] = useState<boolean>(false);
  const [scaleResult, setScaleResult] = useState<CloudScaleResult | null>(null);
  const [hostCmd, setHostCmd] = useState<string>('uptime');
  const [isExecutingCmd, setIsExecutingCmd] = useState<boolean>(false);
  const [cmdResult, setCmdResult] = useState<HostCommandResult | null>(null);

  // Load Test State
  const [targetEps, setTargetEps] = useState<number>(25_000);
  const [testDuration, setTestDuration] = useState<number>(5);
  const [isRunningTest, setIsRunningTest] = useState<boolean>(false);
  const [loadTestResult, setLoadTestResult] = useState<LoadTestRunResult | null>(null);
  const [certificate, setCertificate] = useState<InfraReadinessCertificate | null>(null);

  // Fetch bundle
  const fetchBundle = useCallback(async (cfg: DeploymentConfig) => {
    setIsGenerating(true);
    try {
      const data = await siemApi.generateDeployment(cfg);
      setBundle(data);
      setSelectedFileIndex(0);
    } catch (err) {
      console.error('Failed to generate deployment bundle:', err);
    } finally {
      setIsGenerating(false);
    }
  }, []);

  // Fetch governor status
  const fetchGovernor = useCallback(async () => {
    try {
      const stats = await siemApi.getGovernorStatus();
      setGovernorStats(stats);
    } catch (err) {
      console.error('Failed to fetch governor stats:', err);
    }
  }, []);

  // Fetch host nodes
  const fetchNodes = useCallback(async () => {
    try {
      const nodeList = await siemApi.getInfraNodes();
      setNodes(nodeList);
    } catch (err) {
      console.error('Failed to fetch nodes:', err);
    }
  }, []);

  useEffect(() => {
    fetchBundle(config);
  }, [fetchBundle, config.tier, config.enableSmartSamplingSurge, config.replicaCount, config.wormRetentionDays]);

  useEffect(() => {
    fetchGovernor();
    fetchNodes();
    const timer = setInterval(() => {
      fetchGovernor();
      fetchNodes();
    }, 3000);
    return () => clearInterval(timer);
  }, [fetchGovernor, fetchNodes]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadZip = async () => {
    setIsDownloading(true);
    try {
      const blob = await siemApi.downloadDeploymentZip(config);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `tum-opensiem-deployment-tier${config.tier}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download error:', err);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleToggleSurge = async () => {
    if (!governorStats) return;
    setIsTogglingSurge(true);
    try {
      const updated = await siemApi.configureGovernor({
        forceSurge: !governorStats.forceSurgeMode,
      });
      setGovernorStats(updated);
    } catch (err) {
      console.error('Surge toggle error:', err);
    } finally {
      setIsTogglingSurge(false);
    }
  };

  const handleScaleK8s = async () => {
    setIsScaling(true);
    try {
      const res = await siemApi.scaleInfra({
        provider: 1, // K8s
        namespace: 'security',
        targetDeploymentName: 'tum-opensiem',
        desiredReplicas: k8sReplicas,
      });
      setScaleResult(res);
    } catch (err) {
      console.error('Scale error:', err);
    } finally {
      setIsScaling(false);
    }
  };

  const handleScaleAws = async () => {
    setIsScaling(true);
    try {
      const res = await siemApi.scaleInfra({
        provider: 2, // AWS
        instanceType: awsInstanceType,
        desiredReplicas: awsCount,
      });
      setScaleResult(res);
    } catch (err) {
      console.error('AWS scale error:', err);
    } finally {
      setIsScaling(false);
    }
  };

  const handleExecuteCmd = async () => {
    if (!hostCmd) return;
    setIsExecutingCmd(true);
    try {
      const res = await siemApi.executeHostCommand({
        nodeId: 'local-master-node',
        command: hostCmd,
        timeoutSeconds: 10,
      });
      setCmdResult(res);
    } catch (err) {
      console.error('Command execution error:', err);
    } finally {
      setIsExecutingCmd(false);
    }
  };

  const handleRunLoadTest = async () => {
    setIsRunningTest(true);
    setLoadTestResult(null);
    setCertificate(null);
    try {
      const res = await siemApi.runLoadTest({
        targetEps,
        durationSeconds: testDuration,
      });
      setLoadTestResult(res);
      const cert = await siemApi.generateReadinessCertificate(res);
      setCertificate(cert);
    } catch (err) {
      console.error('Load test error:', err);
    } finally {
      setIsRunningTest(false);
    }
  };

  const handleDownloadCertificate = () => {
    if (!certificate) return;
    const blob = new Blob([JSON.stringify(certificate, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${certificate.certificateId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedFile = bundle?.files[selectedFileIndex] ?? null;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#161b22] border border-[#30363d] p-5 rounded-lg shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <Boxes className="w-5 h-5 text-[#58a6ff]" />
            <h1 className="text-xl font-bold tracking-tight text-[#f0f6fc]">{t.deploymentTitle}</h1>
          </div>
          <p className="text-xs text-[#8b949e] mt-1">{t.deploymentSubtitle}</p>
        </div>

        {/* 3-Tab Sub Navigation */}
        <div className="flex items-center bg-[#0d1117] p-1 rounded border border-[#30363d]">
          <button
            type="button"
            onClick={() => setActiveSubTab('generator')}
            className={`px-3 py-1.5 text-xs font-mono font-semibold rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'generator'
                ? 'bg-[#1f6feb] text-white shadow'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            <Boxes className="w-3.5 h-3.5" />
            {t.subtabDeploymentGenerator}
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab('host-orchestrator')}
            className={`px-3 py-1.5 text-xs font-mono font-semibold rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'host-orchestrator'
                ? 'bg-[#1f6feb] text-white shadow'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            {t.subtabHostTelemetry}
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab('load-test')}
            className={`px-3 py-1.5 text-xs font-mono font-semibold rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'load-test'
                ? 'bg-[#1f6feb] text-white shadow'
                : 'text-[#8b949e] hover:text-[#f0f6fc]'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            {t.subtabLoadTesting}
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUBTAB 1: DOCKER & K8S DEPLOYMENT GENERATOR                               */}
      {/* ========================================================================= */}
      {activeSubTab === 'generator' && (
        <div className="space-y-6">
          {/* Live Surge & Flash Crowd Governor HUD */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#21262d]">
              <div>
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-[#e3b341]" />
                  <h2 className="text-sm font-bold text-[#f0f6fc] uppercase tracking-wider">{t.surgeGovernorTitle}</h2>
                </div>
                <p className="text-xs text-[#8b949e] mt-0.5">{t.retention100Forensic}</p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono font-semibold border ${
                    governorStats?.isSurgeActive
                      ? 'bg-[#d29922]/15 text-[#f0883e] border-[#d29922]/40'
                      : 'bg-[#238636]/15 text-[#3fb950] border-[#238636]/40'
                  }`}
                >
                  <div
                    className={`w-2 h-2 rounded-full ${
                      governorStats?.isSurgeActive ? 'bg-[#f0883e] animate-ping' : 'bg-[#3fb950]'
                    }`}
                  />
                  {governorStats?.isSurgeActive ? t.surgeActive : t.surgeNormal}
                </div>

                <button
                  type="button"
                  onClick={handleToggleSurge}
                  disabled={isTogglingSurge}
                  className="px-3 py-1.5 text-xs font-mono font-medium rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] border border-[#30363d] transition cursor-pointer"
                >
                  {t.btnToggleSurge}: {governorStats?.forceSurgeMode ? 'ON' : 'OFF'}
                </button>
              </div>
            </div>

            {/* Governor Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <span className="text-[11px] text-[#8b949e] block font-mono">Current Ingestion EPS</span>
                <span className="text-lg font-bold font-mono text-[#58a6ff]">
                  {governorStats ? governorStats.currentEps.toLocaleString() : '0'} EPS
                </span>
              </div>

              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <span className="text-[11px] text-[#8b949e] block font-mono">Surge Threshold</span>
                <span className="text-lg font-bold font-mono text-[#f0f6fc]">
                  {governorStats ? governorStats.surgeThresholdEps.toLocaleString() : '10,000'} EPS
                </span>
              </div>

              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <span className="text-[11px] text-[#8b949e] block font-mono">Benign Noise Sampling Ratio</span>
                <span className="text-lg font-bold font-mono text-[#e3b341]">
                  1 : {governorStats ? governorStats.benignSampleRate : 50}
                </span>
              </div>

              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <span className="text-[11px] text-[#8b949e] block font-mono">Forensic Retention Guarantee</span>
                <span className="text-lg font-bold font-mono text-[#3fb950]">100% STRICT</span>
              </div>
            </div>
          </div>

          {/* Tier Selector Cards */}
          <div>
            <h2 className="text-xs font-mono uppercase tracking-wider text-[#8b949e] mb-3">{t.tierSelectTitle}</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Tier 1 */}
              <div
                onClick={() => setConfig({ ...config, tier: 1 as ArchitectureTier })}
                className={`p-4 rounded-lg border transition-all cursor-pointer ${
                  config.tier === 1
                    ? 'bg-[#1f6feb]/10 border-[#1f6feb] shadow-sm'
                    : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <Server className={`w-5 h-5 ${config.tier === 1 ? 'text-[#58a6ff]' : 'text-[#8b949e]'}`} />
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#8b949e]">
                    &lt; 5,000 EPS
                  </span>
                </div>
                <h3 className="text-sm font-bold text-[#f0f6fc]">{t.tier1Name}</h3>
                <p className="text-xs text-[#8b949e] mt-1">{t.tier1Desc}</p>
              </div>

              {/* Tier 2 */}
              <div
                onClick={() => setConfig({ ...config, tier: 2 as ArchitectureTier })}
                className={`p-4 rounded-lg border transition-all cursor-pointer ${
                  config.tier === 2
                    ? 'bg-[#1f6feb]/10 border-[#1f6feb] shadow-sm'
                    : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <Layers className={`w-5 h-5 ${config.tier === 2 ? 'text-[#58a6ff]' : 'text-[#8b949e]'}`} />
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#58a6ff]">
                    5k - 50k EPS
                  </span>
                </div>
                <h3 className="text-sm font-bold text-[#f0f6fc]">{t.tier2Name}</h3>
                <p className="text-xs text-[#8b949e] mt-1">{t.tier2Desc}</p>
              </div>

              {/* Tier 3 */}
              <div
                onClick={() => setConfig({ ...config, tier: 3 as ArchitectureTier })}
                className={`p-4 rounded-lg border transition-all cursor-pointer relative overflow-hidden ${
                  config.tier === 3
                    ? 'bg-[#1f6feb]/10 border-[#1f6feb] shadow-sm'
                    : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]/50'
                }`}
              >
                <div className="absolute top-0 right-0 bg-[#f0883e] text-black font-bold text-[9px] px-2 py-0.5 rounded-bl">
                  OCSC / ก.พ. READY
                </div>
                <div className="flex items-center justify-between mb-2">
                  <Boxes className={`w-5 h-5 ${config.tier === 3 ? 'text-[#58a6ff]' : 'text-[#8b949e]'}`} />
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#3fb950]">
                    &gt; 100k EPS
                  </span>
                </div>
                <h3 className="text-sm font-bold text-[#f0f6fc]">{t.tier3Name}</h3>
                <p className="text-xs text-[#8b949e] mt-1">{t.tier3Desc}</p>
              </div>
            </div>
          </div>

          {/* Hardware Spec & Sizing Blueprint */}
          {bundle && (
            <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5">
              <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#21262d]">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-[#58a6ff]" />
                  <h3 className="text-xs font-mono uppercase tracking-wider text-[#f0f6fc]">
                    {t.hardwareSpecTitle} ({bundle.tierName})
                  </h3>
                </div>
                <span className="text-xs text-[#8b949e] italic">{bundle.targetScenario}</span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <Cpu className="w-3 h-3 text-[#58a6ff]" /> CPU Cores
                  </span>
                  <span className="text-xs font-bold text-[#f0f6fc] mt-1 block">{bundle.hardware.minCpu}</span>
                </div>

                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <HardDrive className="w-3 h-3 text-[#3fb950]" /> RAM Memory
                  </span>
                  <span className="text-xs font-bold text-[#f0f6fc] mt-1 block">{bundle.hardware.minRam}</span>
                </div>

                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <HardDrive className="w-3 h-3 text-[#e3b341]" /> Storage Medium
                  </span>
                  <span className="text-xs font-bold text-[#f0f6fc] mt-1 block">{bundle.hardware.storageType}</span>
                </div>

                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <Network className="w-3 h-3 text-[#bc8cff]" /> Network Fabric
                  </span>
                  <span className="text-xs font-bold text-[#f0f6fc] mt-1 block">{bundle.hardware.networkBandwidth}</span>
                </div>

                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <Zap className="w-3 h-3 text-[#58a6ff]" /> Max Sustained EPS
                  </span>
                  <span className="text-xs font-bold text-[#58a6ff] mt-1 block font-mono">
                    {bundle.hardware.maxSustainedEps}
                  </span>
                </div>

                <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                  <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1">
                    <Boxes className="w-3 h-3 text-[#f0883e]" /> Peak Concurrency
                  </span>
                  <span className="text-xs font-bold text-[#f0883e] mt-1 block font-mono">
                    {bundle.hardware.peakConcurrencyUsers}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Manifest Viewer & Code Block */}
          {bundle && (
            <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
              <div className="flex items-center justify-between bg-[#0d1117] border-b border-[#30363d] px-4 pt-2 overflow-x-auto">
                <div className="flex items-center gap-1">
                  {bundle.files.map((file, idx) => (
                    <button
                      key={file.path}
                      type="button"
                      onClick={() => setSelectedFileIndex(idx)}
                      className={`px-3 py-2 text-xs font-mono rounded-t transition cursor-pointer border-t-2 ${
                        selectedFileIndex === idx
                          ? 'bg-[#161b22] text-[#f0f6fc] border-[#1f6feb] font-semibold'
                          : 'text-[#8b949e] hover:text-[#f0f6fc] border-transparent'
                      }`}
                    >
                      {file.path}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-2 py-1">
                  {isGenerating && (
                    <span className="text-[11px] font-mono text-[#8b949e] animate-pulse">Generating...</span>
                  )}
                  <button
                    type="button"
                    onClick={() => selectedFile && handleCopy(selectedFile.content)}
                    className="flex items-center gap-1.5 px-3 py-1 text-xs rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] border border-[#30363d] cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-[#3fb950]" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? t.btnCopied : t.btnCopyCode}
                  </button>

                  <button
                    type="button"
                    onClick={handleDownloadZip}
                    disabled={isDownloading}
                    className="flex items-center gap-1.5 px-3 py-1 text-xs rounded bg-[#238636] hover:bg-[#2ea043] text-white font-semibold cursor-pointer disabled:opacity-50"
                  >
                    <Download className="w-3.5 h-3.5" />
                    {isDownloading ? t.btnDownloading : t.btnDownloadZip}
                  </button>
                </div>
              </div>

              {selectedFile && (
                <div className="bg-[#161b22] px-4 py-2 border-b border-[#21262d] text-xs text-[#8b949e] flex items-center justify-between">
                  <span>{selectedFile.description}</span>
                  <span className="font-mono text-[11px] text-[#58a6ff] uppercase">{selectedFile.language}</span>
                </div>
              )}

              <div className="p-4 bg-[#0d1117] overflow-x-auto">
                <pre className="text-xs font-mono text-[#c9d1d9] leading-relaxed select-text">
                  <code>{selectedFile?.content}</code>
                </pre>
              </div>

              <div className="bg-[#161b22] p-4 border-t border-[#30363d] flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#3fb950]" />
                  <span className="text-xs text-[#8b949e] font-mono">Quick-Start Launch:</span>
                  <code className="text-xs font-mono bg-[#0d1117] text-[#3fb950] px-2 py-1 rounded border border-[#21262d]">
                    {bundle.quickStartCommand}
                  </code>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopy(bundle.quickStartCommand)}
                  className="text-xs text-[#58a6ff] hover:underline cursor-pointer flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" /> Copy Command
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 2: LIVE HOST OBSERVER & CLOUD ORCHESTRATOR (Zabbix-like HUD)       */}
      {/* ========================================================================= */}
      {activeSubTab === 'host-orchestrator' && (
        <div className="space-y-6">
          {/* Host Nodes List (Zabbix-like Cards) */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold text-[#f0f6fc] flex items-center gap-2">
                <Server className="w-4 h-4 text-[#58a6ff]" />
                {t.nodesTitle}
              </h2>
              <button
                type="button"
                onClick={fetchNodes}
                className="text-xs text-[#8b949e] hover:text-[#f0f6fc] flex items-center gap-1 font-mono cursor-pointer"
              >
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {nodes.map((node) => (
                <div key={node.nodeId} className="bg-[#161b22] border border-[#30363d] rounded-lg p-5 space-y-4">
                  {/* Node Header */}
                  <div className="flex items-center justify-between border-b border-[#21262d] pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-[#f0f6fc]">{node.hostname}</h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#8b949e]">
                          {node.ipAddress}
                        </span>
                      </div>
                      <span className="text-[11px] text-[#8b949e] font-mono">{node.osDescription}</span>
                    </div>

                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#238636]/15 text-[#3fb950] text-xs font-mono font-semibold border border-[#238636]/30">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      HEALTHY
                    </div>
                  </div>

                  {/* Resource Gauges */}
                  <div className="grid grid-cols-3 gap-3">
                    {/* CPU */}
                    <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                      <div className="flex items-center justify-between text-[11px] text-[#8b949e] font-mono">
                        <span>CPU Usage</span>
                        <span>{node.cpuCoreCount} Cores</span>
                      </div>
                      <div className="mt-1 flex items-baseline gap-1">
                        <span className="text-lg font-bold font-mono text-[#58a6ff]">{node.cpuUsagePercent}%</span>
                      </div>
                      <div className="w-full bg-[#21262d] h-1.5 rounded-full mt-2 overflow-hidden">
                        <div
                          className="bg-[#58a6ff] h-full rounded-full transition-all duration-500"
                          style={{ width: `${Math.min(100, node.cpuUsagePercent)}%` }}
                        />
                      </div>
                    </div>

                    {/* RAM */}
                    <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                      <div className="flex items-center justify-between text-[11px] text-[#8b949e] font-mono">
                        <span>Memory</span>
                        <span>{Math.round(node.totalMemoryBytes / (1024 * 1024 * 1024))} GB</span>
                      </div>
                      <div className="mt-1 flex items-baseline gap-1">
                        <span className="text-lg font-bold font-mono text-[#3fb950]">
                          {node.memoryUsagePercent.toFixed(1)}%
                        </span>
                        <span className="text-[10px] text-[#8b949e] font-mono">
                          ({(node.usedMemoryBytes / (1024 * 1024)).toFixed(0)} MB used)
                        </span>
                      </div>
                      <div className="w-full bg-[#21262d] h-1.5 rounded-full mt-2 overflow-hidden">
                        <div
                          className="bg-[#3fb950] h-full rounded-full transition-all duration-500"
                          style={{ width: `${Math.min(100, node.memoryUsagePercent)}%` }}
                        />
                      </div>
                    </div>

                    {/* TCP Sockets */}
                    <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                      <div className="flex items-center justify-between text-[11px] text-[#8b949e] font-mono">
                        <span>Sockets</span>
                        <span>Active Sockets</span>
                      </div>
                      <div className="mt-1 flex items-baseline gap-1">
                        <span className="text-lg font-bold font-mono text-[#e3b341]">
                          {node.tcpEstablishedCount} ESTAB
                        </span>
                      </div>
                      <span className="text-[10px] text-[#8b949e] font-mono block mt-1">
                        {node.tcpListenCount} Listen | {node.tcpTimeWaitCount} TimeWait
                      </span>
                    </div>
                  </div>

                  {/* Disks Table */}
                  {node.disks && node.disks.length > 0 && (
                    <div className="bg-[#0d1117] p-3 rounded border border-[#21262d] text-xs">
                      <div className="text-[11px] text-[#8b949e] font-mono mb-2 flex items-center gap-1">
                        <HardDrive className="w-3.5 h-3.5" /> Mounted Storage Volumes
                      </div>
                      <div className="space-y-1.5">
                        {node.disks.map((d) => (
                          <div key={d.mountPoint} className="flex items-center justify-between font-mono text-[11px]">
                            <span className="text-[#f0f6fc]">{d.mountPoint}</span>
                            <span className="text-[#8b949e]">
                              {Math.round((d.totalBytes - d.freeBytes) / (1024 * 1024 * 1024))} /{' '}
                              {Math.round(d.totalBytes / (1024 * 1024 * 1024))} GB ({d.usagePercent}%)
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Cloud & Cluster Orchestration Controls */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5 space-y-5">
            <div className="border-b border-[#21262d] pb-3">
              <h2 className="text-sm font-bold text-[#f0f6fc] flex items-center gap-2">
                <Cloud className="w-4 h-4 text-[#58a6ff]" />
                {t.orchestratorTitle}
              </h2>
              <p className="text-xs text-[#8b949e] mt-1">
                Dispatch dynamic scaling commands directly to Kubernetes API, AWS EC2, or execute Sentinel-guarded host diagnostics.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Kubernetes Scaler */}
              <div className="bg-[#0d1117] p-4 rounded border border-[#21262d] space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Boxes className="w-4 h-4 text-[#3fb950]" />
                    <span className="text-xs font-bold font-mono text-[#f0f6fc]">Kubernetes Pod Autoscaler</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#3fb950]">
                    K8s API Ready
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-[#8b949e]">Desired Ingestion Pods:</span>
                    <span className="text-[#58a6ff] font-bold text-sm">{k8sReplicas} Replicas</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={32}
                    value={k8sReplicas}
                    onChange={(e) => setK8sReplicas(parseInt(e.target.value, 10))}
                    className="w-full accent-[#1f6feb] cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] text-[#8b949e] font-mono">
                    <span>1 Pod (5k EPS)</span>
                    <span>16 Pods (80k EPS)</span>
                    <span>32 Pods (160k EPS)</span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleScaleK8s}
                  disabled={isScaling}
                  className="w-full py-2 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white text-xs font-semibold font-mono transition cursor-pointer disabled:opacity-50"
                >
                  {isScaling ? 'Scaling...' : `${t.btnScaleK8s} (${k8sReplicas} Pods)`}
                </button>
              </div>

              {/* AWS EC2 Provisioner */}
              <div className="bg-[#0d1117] p-4 rounded border border-[#21262d] space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Cloud className="w-4 h-4 text-[#e3b341]" />
                    <span className="text-xs font-bold font-mono text-[#f0f6fc]">AWS EC2 Auto-Provisioning</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#21262d] text-[#e3b341]">
                    EI-VS Calibrated
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <label className="text-[#8b949e] block mb-1">Instance Type:</label>
                    <select
                      value={awsInstanceType}
                      onChange={(e) => setAwsInstanceType(e.target.value)}
                      className="w-full bg-[#161b22] border border-[#30363d] rounded p-1.5 text-[#f0f6fc]"
                    >
                      <option value="c6i.4xlarge">c6i.4xlarge (16 vCPU, 32GB)</option>
                      <option value="c6i.8xlarge">c6i.8xlarge (32 vCPU, 64GB)</option>
                      <option value="r6i.4xlarge">r6i.4xlarge (16 vCPU, 128GB)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[#8b949e] block mb-1">Instance Count:</label>
                    <input
                      type="number"
                      min={1}
                      max={8}
                      value={awsCount}
                      onChange={(e) => setAwsCount(parseInt(e.target.value, 10))}
                      className="w-full bg-[#161b22] border border-[#30363d] rounded p-1.5 text-[#f0f6fc]"
                    />
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleScaleAws}
                  disabled={isScaling}
                  className="w-full py-2 rounded bg-[#21262d] hover:bg-[#30363d] text-[#f0f6fc] border border-[#30363d] text-xs font-semibold font-mono transition cursor-pointer disabled:opacity-50"
                >
                  {isScaling ? 'Dispatching...' : `${t.btnScaleAws} (${awsCount}x ${awsInstanceType})`}
                </button>
              </div>
            </div>

            {/* Orchestration Execution Result Banner */}
            {scaleResult && (
              <div
                className={`p-3 rounded text-xs font-mono border ${
                  scaleResult.success
                    ? 'bg-[#238636]/10 border-[#238636]/30 text-[#3fb950]'
                    : 'bg-[#d29922]/10 border-[#d29922]/30 text-[#f0883e]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold">{scaleResult.providerAttribution}</span>
                  <span className="text-[10px] text-[#8b949e]">
                    {new Date(scaleResult.executedAtUtc).toLocaleTimeString()}
                  </span>
                </div>
                <p className="mt-1">{scaleResult.message}</p>
              </div>
            )}

            {/* Host Diagnostic Terminal */}
            <div className="bg-[#0d1117] p-4 rounded border border-[#21262d] space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#58a6ff]" />
                  <span className="text-xs font-bold font-mono text-[#f0f6fc]">
                    Sentinel-Guarded Host Diagnostic Terminal
                  </span>
                </div>
                <span className="text-[10px] font-mono text-[#8b949e]">Safe Commands Only (Destructive Blocked)</span>
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={hostCmd}
                  onChange={(e) => setHostCmd(e.target.value)}
                  placeholder="e.g. uptime, docker ps, hostname"
                  className="flex-grow bg-[#161b22] border border-[#30363d] rounded px-3 py-1.5 text-xs font-mono text-[#f0f6fc]"
                />
                <button
                  type="button"
                  onClick={handleExecuteCmd}
                  disabled={isExecutingCmd}
                  className="px-4 py-1.5 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white text-xs font-semibold font-mono cursor-pointer disabled:opacity-50"
                >
                  {isExecutingCmd ? 'Executing...' : 'Execute'}
                </button>
              </div>

              {cmdResult && (
                <div className="bg-[#161b22] p-3 rounded border border-[#21262d] text-xs font-mono">
                  <div className="flex items-center justify-between text-[10px] text-[#8b949e] pb-1 border-b border-[#21262d] mb-2">
                    <span>Exit Code: {cmdResult.exitCode}</span>
                    <span>Duration: {cmdResult.executionDurationMs.toFixed(1)} ms</span>
                  </div>
                  {cmdResult.standardOutput && (
                    <pre className="text-[#c9d1d9] whitespace-pre-wrap">{cmdResult.standardOutput}</pre>
                  )}
                  {cmdResult.standardError && (
                    <pre className="text-[#f85149] whitespace-pre-wrap">{cmdResult.standardError}</pre>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 3: LOAD TESTING & INFRASTRUCTURE READINESS SUITE                   */}
      {/* ========================================================================= */}
      {activeSubTab === 'load-test' && (
        <div className="space-y-6">
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5 space-y-4">
            <div className="border-b border-[#21262d] pb-3 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-[#f0f6fc] flex items-center gap-2">
                  <Play className="w-4 h-4 text-[#58a6ff]" />
                  {t.loadTestTitle}
                </h2>
                <p className="text-xs text-[#8b949e] mt-0.5">
                  Inject high-speed synthetic telemetry directly into the OpenSIEM RingBuffer pipeline to empirically verify sustained throughput and certify peak flash crowd capacity.
                </p>
              </div>

              {certificate && (
                <button
                  type="button"
                  onClick={handleDownloadCertificate}
                  className="flex items-center gap-2 px-3 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold cursor-pointer shadow"
                >
                  <Award className="w-4 h-4" />
                  {t.btnGenerateCert}
                </button>
              )}
            </div>

            {/* Load Test Parameters */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <label className="text-[11px] font-mono text-[#8b949e] block mb-1">Target Ingestion Rate (EPS):</label>
                <select
                  value={targetEps}
                  onChange={(e) => setTargetEps(parseInt(e.target.value, 10))}
                  className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs font-mono text-[#f0f6fc]"
                >
                  <option value={5000}>5,000 EPS (Single-Node Lab)</option>
                  <option value={20000}>20,000 EPS (Standard Enterprise)</option>
                  <option value={50000}>50,000 EPS (High-Throughput Cluster)</option>
                  <option value={100000}>100,000 EPS (National Flash Crowd / ก.พ.)</option>
                </select>
              </div>

              <div className="bg-[#0d1117] p-3 rounded border border-[#21262d]">
                <label className="text-[11px] font-mono text-[#8b949e] block mb-1">Test Duration:</label>
                <select
                  value={testDuration}
                  onChange={(e) => setTestDuration(parseInt(e.target.value, 10))}
                  className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs font-mono text-[#f0f6fc]"
                >
                  <option value={3}>3 Seconds (Quick Smoke Benchmark)</option>
                  <option value={5}>5 Seconds (Standard Soak Test)</option>
                  <option value={15}>15 Seconds (Deep Saturation Test)</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="button"
                  onClick={handleRunLoadTest}
                  disabled={isRunningTest}
                  className="w-full py-2.5 rounded bg-[#1f6feb] hover:bg-[#388bfd] text-white text-xs font-semibold font-mono flex items-center justify-center gap-2 cursor-pointer shadow disabled:opacity-50"
                >
                  <Play className="w-4 h-4" />
                  {isRunningTest ? t.btnRunningTest : t.btnRunLoadTest}
                </button>
              </div>
            </div>

            {/* Test Results Card */}
            {loadTestResult && (
              <div className="bg-[#0d1117] p-5 rounded border border-[#21262d] space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-[#21262d]">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#3fb950]" />
                    <span className="text-xs font-bold font-mono text-[#f0f6fc]">Benchmark Execution Report</span>
                  </div>
                  <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#238636]/20 text-[#3fb950] border border-[#238636]/40">
                    {loadTestResult.verdict}
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <span className="text-[11px] text-[#8b949e] font-mono block">Achieved Average Throughput</span>
                    <span className="text-xl font-bold font-mono text-[#58a6ff]">
                      {loadTestResult.averageEps.toLocaleString()} EPS
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-[#8b949e] font-mono block">Total Ingested Events</span>
                    <span className="text-xl font-bold font-mono text-[#3fb950]">
                      {loadTestResult.totalEventsIngested.toLocaleString()}
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-[#8b949e] font-mono block">Latency Percentiles</span>
                    <span className="text-xs font-bold font-mono text-[#f0f6fc] block mt-1">
                      p50: {loadTestResult.latencyP50Ms}ms | p99: {loadTestResult.latencyP99Ms}ms
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-[#8b949e] font-mono block">Memory Working Set</span>
                    <span className="text-xl font-bold font-mono text-[#e3b341]">
                      {(loadTestResult.peakMemoryBytes / (1024 * 1024)).toFixed(0)} MB
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Cryptographically Sealed Certificate Box */}
            {certificate && (
              <div className="bg-[#161b22] border-2 border-[#1f6feb]/40 rounded-lg p-5 space-y-3 relative overflow-hidden">
                <div className="absolute top-0 right-0 bg-[#1f6feb] text-white font-mono text-[10px] px-3 py-1 rounded-bl">
                  OFFICIAL AUDIT ATTESTATION
                </div>

                <div className="flex items-center gap-2">
                  <Award className="w-5 h-5 text-[#58a6ff]" />
                  <h3 className="text-sm font-bold text-[#f0f6fc]">
                    {certificate.targetSystemName} — Infrastructure Readiness Certificate
                  </h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="bg-[#0d1117] p-3 rounded">
                    <span className="text-[#8b949e] block text-[10px]">Certificate ID</span>
                    <span className="text-[#f0f6fc] font-bold">{certificate.certificateId}</span>
                  </div>

                  <div className="bg-[#0d1117] p-3 rounded">
                    <span className="text-[#8b949e] block text-[10px]">Evaluation Verdict</span>
                    <span className="text-[#3fb950] font-bold">{certificate.evaluationVerdict}</span>
                  </div>

                  <div className="bg-[#0d1117] p-3 rounded">
                    <span className="text-[#8b949e] block text-[10px]">Certified Capacity</span>
                    <span className="text-[#58a6ff] font-bold">
                      {certificate.estimatedConcurrentCapacity.toLocaleString()} Concurrent Applicants
                    </span>
                  </div>
                </div>

                <div className="bg-[#0d1117] p-3 rounded space-y-1">
                  <span className="text-[11px] font-mono text-[#8b949e] block font-semibold">Verified Capabilities:</span>
                  {certificate.verifiedCapabilities.map((cap, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-xs text-[#c9d1d9]">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#3fb950] shrink-0" />
                      <span>{cap}</span>
                    </div>
                  ))}
                </div>

                <div className="text-[10px] font-mono text-[#8b949e] flex items-center justify-between pt-2 border-t border-[#21262d]">
                  <span>SHA-256 Merkle Seal: {certificate.cryptographicAttestationHash.slice(0, 32)}...</span>
                  <span>Issued: {new Date(certificate.issuedAtUtc).toISOString()}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
