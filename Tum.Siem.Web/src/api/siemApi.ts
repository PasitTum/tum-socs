// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import type {
  AttackGraphData,
  ComplianceAuditSummary,
  EventQueryResult,
  IngestLogResponse,
  RegisterSigmaRuleResult,
  SigmaRulesSummary,
  SystemStatus,
  ThreatDashboardSummary,
  TumLogEntry,
} from '../types/siem';
import type {
  DatasetCatalogResponse,
  DatasetOperationResult,
  LoginResponse,
  UserProfile,
} from '../types/auth';

const API_BASE = '/api';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('tum_siem_token');
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    localStorage.removeItem('tum_siem_token');
    localStorage.removeItem('tum_siem_user');
  }

  if (!res.ok) {
    let errorDetail = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const data = await res.json();
      if (data.detail) errorDetail = data.detail;
      else if (data.title) errorDetail = data.title;
      else if (data.message) errorDetail = data.message;
    } catch {
      // fallback
    }
    throw new Error(errorDetail);
  }
  return res.json() as Promise<T>;
}

export const siemApi = {
  // Authentication Endpoints
  async login(username: string, password: string): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await handleResponse<LoginResponse>(res);
    localStorage.setItem('tum_siem_token', data.token);
    localStorage.setItem('tum_siem_user', JSON.stringify(data.user));
    return data;
  },

  async getCurrentUser(): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<UserProfile>(res);
  },

  logout(): void {
    fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
    }).catch(() => {});
    localStorage.removeItem('tum_siem_token');
    localStorage.removeItem('tum_siem_user');
  },

  // Dataset Management & Production Clean Reset
  async getDatasetCatalog(): Promise<DatasetCatalogResponse> {
    const res = await fetch(`${API_BASE}/dataset/catalog`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<DatasetCatalogResponse>(res);
  },

  async loadDataset(datasetId = 'all', limit = 50): Promise<DatasetOperationResult> {
    const res = await fetch(`${API_BASE}/dataset/load`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ datasetId, limit }),
    });
    return handleResponse<DatasetOperationResult>(res);
  },

  async purgeDataForProduction(): Promise<DatasetOperationResult> {
    const res = await fetch(`${API_BASE}/dataset/purge`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
    });
    return handleResponse<DatasetOperationResult>(res);
  },

  // SIEM Core Endpoints
  async getStatus(): Promise<SystemStatus> {
    const res = await fetch(`${API_BASE}/status`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<SystemStatus>(res);
  },

  async getDashboardSummary(): Promise<ThreatDashboardSummary> {
    const res = await fetch(`${API_BASE}/dashboard/summary`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<ThreatDashboardSummary>(res);
  },

  async getAttackGraph(limit = 50): Promise<AttackGraphData> {
    const res = await fetch(`${API_BASE}/dashboard/attack-graph?limit=${limit}`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<AttackGraphData>(res);
  },

  async getComplianceReport(): Promise<ComplianceAuditSummary> {
    const res = await fetch(`${API_BASE}/dashboard/compliance`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<ComplianceAuditSummary>(res);
  },

  async getLiveEvents(limit = 30): Promise<TumLogEntry[]> {
    const res = await fetch(`${API_BASE}/logs/live?limit=${limit}`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<TumLogEntry[]>(res);
  },

  async queryLogs(query = '*', limit = 100, offset = 0): Promise<EventQueryResult> {
    const params = new URLSearchParams({
      query,
      limit: limit.toString(),
      offset: offset.toString(),
    });
    const res = await fetch(`${API_BASE}/logs/query?${params.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<EventQueryResult>(res);
  },

  async ingestLog(entry: Partial<TumLogEntry>): Promise<IngestLogResponse> {
    const res = await fetch(`${API_BASE}/logs/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(entry),
    });
    return handleResponse<IngestLogResponse>(res);
  },

  async getSigmaRulesSummary(): Promise<SigmaRulesSummary> {
    const res = await fetch(`${API_BASE}/sigma/rules`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<SigmaRulesSummary>(res);
  },

  async registerSigmaRule(yamlContent: string): Promise<RegisterSigmaRuleResult> {
    const res = await fetch(`${API_BASE}/sigma/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', ...getAuthHeader() },
      body: yamlContent,
    });
    return handleResponse<RegisterSigmaRuleResult>(res);
  },

  // Deployment Generator Endpoints
  async generateDeployment(config: Partial<import('../types/siem').DeploymentConfig>): Promise<import('../types/siem').DeploymentBundle> {
    const res = await fetch(`${API_BASE}/deployment/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(config),
    });
    return handleResponse<import('../types/siem').DeploymentBundle>(res);
  },

  async downloadDeploymentZip(config: Partial<import('../types/siem').DeploymentConfig>): Promise<Blob> {
    const res = await fetch(`${API_BASE}/deployment/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      throw new Error(`Failed to download deployment package: ${res.statusText}`);
    }
    return res.blob();
  },

  // Smart Sampling & Flash Crowd Governor Endpoints
  async getGovernorStatus(): Promise<import('../types/siem').GovernorStats> {
    const res = await fetch(`${API_BASE}/governor/status`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<import('../types/siem').GovernorStats>(res);
  },

  async configureGovernor(config: { forceSurge?: boolean; surgeThresholdEps?: number; benignSampleRate?: number }): Promise<import('../types/siem').GovernorStats> {
    const res = await fetch(`${API_BASE}/governor/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(config),
    });
    return handleResponse<import('../types/siem').GovernorStats>(res);
  },

  // Live Host Telemetry & Cloud Orchestration Endpoints
  async getInfraNodes(): Promise<import('../types/siem').HostNodeMetrics[]> {
    const res = await fetch(`${API_BASE}/infra/nodes`, {
      headers: { ...getAuthHeader() },
    });
    return handleResponse<import('../types/siem').HostNodeMetrics[]>(res);
  },

  async scaleInfra(request: Partial<import('../types/siem').CloudScaleRequest>): Promise<import('../types/siem').CloudScaleResult> {
    const res = await fetch(`${API_BASE}/infra/orchestrate/scale`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(request),
    });
    return handleResponse<import('../types/siem').CloudScaleResult>(res);
  },

  async executeHostCommand(request: import('../types/siem').HostCommandRequest): Promise<import('../types/siem').HostCommandResult> {
    const res = await fetch(`${API_BASE}/infra/orchestrate/command`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(request),
    });
    return handleResponse<import('../types/siem').HostCommandResult>(res);
  },

  async runLoadTest(scenario: Partial<import('../types/siem').LoadTestScenario>): Promise<import('../types/siem').LoadTestRunResult> {
    const res = await fetch(`${API_BASE}/infra/loadtest/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(scenario),
    });
    return handleResponse<import('../types/siem').LoadTestRunResult>(res);
  },

  async generateReadinessCertificate(result?: Partial<import('../types/siem').LoadTestRunResult>): Promise<import('../types/siem').InfraReadinessCertificate> {
    const res = await fetch(`${API_BASE}/infra/loadtest/certificate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(result ?? {}),
    });
    return handleResponse<import('../types/siem').InfraReadinessCertificate>(res);
  },
};
