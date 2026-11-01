// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, type ActiveTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { MobileBottomNav } from './components/layout/MobileBottomNav';
import { MetricCards } from './components/dashboard/MetricCards';
import { RealtimeChart } from './components/dashboard/RealtimeChart';
import { LiveAttackFeed } from './components/dashboard/LiveAttackFeed';
import { AttackGraphView } from './components/dashboard/AttackGraphView';
import { LogExplorerView } from './components/explorer/LogExplorerView';
import { SigmaRulesView } from './components/rules/SigmaRulesView';
import { ComplianceView } from './components/compliance/ComplianceView';
import { AttackSimulatorModal } from './components/simulation/AttackSimulatorModal';
import { DatasetManagerModal } from './components/datasets/DatasetManagerModal';
import { CyberRangeModal } from './components/range/CyberRangeModal';
import { ScanResultModal } from './components/common/ScanResultModal';
import { CyberNotificationModal, type NotificationState } from './components/common/CyberNotificationModal';
import { LoginPage } from './components/auth/LoginPage';
import { siemApi } from './api/siemApi';
import type {
  SystemStatus,
  ThreatDashboardSummary,
  AttackGraphData,
  TumLogEntry,
  IngestLogResponse,
} from './types/siem';
import type { UserProfile } from './types/auth';
import type { Language } from './i18n/translations';

export const App: React.FC = () => {
  // Authentication State
  const [user, setUser] = useState<UserProfile | null>(() => {
    const saved = localStorage.getItem('tum_siem_user');
    return saved ? JSON.parse(saved) : null;
  });

  // Language State (Persisted in localStorage)
  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem('tum_siem_lang');
    return saved === 'en' ? 'en' : 'th';
  });

  const handleLanguageChange = (newLang: Language) => {
    setLang(newLang);
    localStorage.setItem('tum_siem_lang', newLang);
  };

  const handleLogout = () => {
    siemApi.logout();
    setUser(null);
  };

  // SIEM Console State
  const [activeTab, setActiveTab] = useState<ActiveTab>('radar');
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [summary, setSummary] = useState<ThreatDashboardSummary | null>(null);
  const [attackGraph, setAttackGraph] = useState<AttackGraphData | null>(null);
  const [liveEvents, setLiveEvents] = useState<TumLogEntry[]>([]);
  const [chartData, setChartData] = useState<number[]>([15, 20, 18, 25, 22, 19, 30, 28, 35, 40, 22, 18, 25, 20]);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState<boolean>(false);
  const [isDatasetOpen, setIsDatasetOpen] = useState<boolean>(false);
  const [isCyberRangeOpen, setIsCyberRangeOpen] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isScanResultOpen, setIsScanResultOpen] = useState<boolean>(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);
  const [notification, setNotification] = useState<NotificationState>({
    isOpen: false,
    type: 'info',
    title: '',
    message: '',
  });

  // Sync Telemetry
  const fetchTelemetry = useCallback(async () => {
    if (!user) return;
    try {
      const [statusData, summaryData, eventsData, graphData] = await Promise.all([
        siemApi.getStatus().catch(() => null),
        siemApi.getDashboardSummary().catch(() => null),
        siemApi.getLiveEvents(25).catch(() => []),
        siemApi.getAttackGraph(50).catch(() => null),
      ]);

      if (statusData) setStatus(statusData);
      if (summaryData) setSummary(summaryData);
      if (eventsData && eventsData.length > 0) setLiveEvents(eventsData);
      if (graphData) setAttackGraph(graphData);
    } catch (err) {
      console.error('Failed to sync telemetry:', err);
    }
  }, [user]);

  useEffect(() => {
    if (!user) return;
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 3000);
    return () => clearInterval(interval);
  }, [user, fetchTelemetry]);

  const handleAttackInjected = (response: IngestLogResponse) => {
    setChartData((prev) => [...prev.slice(1), Math.max(response.riskScore, 20)]);
    fetchTelemetry();
  };

  const handleDatasetChanged = () => {
    fetchTelemetry();
  };

  const handleExportAudit = async () => {
    try {
      const data = await siemApi.getComplianceReport();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TUM-EXECUTIVE-AUDIT-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setNotification({
        isOpen: true,
        type: 'error',
        title: lang === 'th' ? 'เกิดข้อผิดพลาดในการส่งออก' : 'Export Error',
        message:
          lang === 'th'
            ? 'ไม่สามารถดึงข้อมูลพยานหลักฐานการตรวจสอบตามกฎหมายได้ กรุณาลองใหม่อีกครั้ง'
            : 'Unable to retrieve legal compliance audit evidence. Please try again.',
      });
    }
  };

  const handleTriggerScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      setIsScanResultOpen(true);
    }, 1200);
  };

  // If user is not authenticated, render Login Portal
  if (!user) {
    return (
      <LoginPage
        onLoginSuccess={(loggedInUser) => setUser(loggedInUser)}
        lang={lang}
        onLanguageChange={handleLanguageChange}
      />
    );
  }

  return (
    <div className="flex min-h-screen bg-[#030712] text-slate-100 selection:bg-cyan-500 selection:text-black">
      {/* Sidebar Navigation (Desktop persistent + Mobile Drawer) */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        status={status}
        user={user}
        lang={lang}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* Main Content Area */}
      <main className="flex-grow p-4 sm:p-6 lg:p-8 pb-24 lg:pb-8 overflow-y-auto max-w-[1700px] mx-auto w-full">
        <Header
          activeTab={activeTab}
          onOpenSimulator={() => setIsSimulatorOpen(true)}
          onOpenDatasets={() => setIsDatasetOpen(true)}
          onOpenCyberRange={() => setIsCyberRangeOpen(true)}
          onExportAudit={handleExportAudit}
          onTriggerScan={handleTriggerScan}
          onLogout={handleLogout}
          isScanning={isScanning}
          lang={lang}
          onLanguageChange={handleLanguageChange}
          onToggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        />

        {/* Tab 1: Radar & HUD */}
        {activeTab === 'radar' && (
          <div className="space-y-6">
            <MetricCards summary={summary} status={status} lang={lang} />
            <RealtimeChart dataPoints={chartData} lang={lang} />

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <LiveAttackFeed events={liveEvents} lang={lang} />
              <AttackGraphView data={attackGraph} lang={lang} />
            </div>
          </div>
        )}

        {/* Tab 2: Event Query Explorer */}
        {activeTab === 'explorer' && <LogExplorerView />}

        {/* Tab 3: Correlated Attack Graph */}
        {activeTab === 'graph' && (
          <div className="space-y-6">
            <AttackGraphView
              data={attackGraph}
              onRefresh={() => siemApi.getAttackGraph(50).then((g) => setAttackGraph(g))}
              lang={lang}
            />
          </div>
        )}

        {/* Tab 4: SigmaHQ Rules */}
        {activeTab === 'rules' && <SigmaRulesView />}

        {/* Tab 5: Regulatory Compliance & WORM Ledger */}
        {activeTab === 'compliance' && <ComplianceView />}
      </main>

      {/* Red-Team Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onAttackInjected={handleAttackInjected}
      />

      {/* Real Datasets & Production Clean Reset Modal */}
      <DatasetManagerModal
        isOpen={isDatasetOpen}
        onClose={() => setIsDatasetOpen(false)}
        onDatasetChanged={handleDatasetChanged}
        lang={lang}
      />

      {/* Enterprise Multi-Layer Cyber Range Modal */}
      <CyberRangeModal
        isOpen={isCyberRangeOpen}
        onClose={() => setIsCyberRangeOpen(false)}
        lang={lang}
      />

      {/* Full-Spectrum Security Scan Result Modal */}
      <ScanResultModal
        isOpen={isScanResultOpen}
        onClose={() => setIsScanResultOpen(false)}
        lang={lang}
      />

      {/* Global Cyber Notification / Error Modal */}
      <CyberNotificationModal
        notification={notification}
        onClose={() => setNotification((prev) => ({ ...prev, isOpen: false }))}
      />

      {/* Mobile & Tablet Bottom Navigation Bar */}
      <MobileBottomNav
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        lang={lang}
      />
    </div>
  );
};

export default App;
