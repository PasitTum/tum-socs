// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

export interface SystemStatus {
  engine: string;
  version: string;
  status: string;
  chainIntact: boolean;
  lastTamperProofHash: string;
  globalMerkleRoot: string;
  activeSigmaRules: number;
  ntpSynchronizedWith: string;
  wormRetentionDays: number;
  timestampUtc: string;
}

export interface ThreatDashboardSummary {
  totalEventsIngested: number;
  currentEventsPerSecond: number;
  criticalAlertsCount: number;
  highAlertsCount: number;
  mediumAlertsCount: number;
  lowAlertsCount: number;
  activeSigmaRulesCount: number;
  totalPiiRedacted: number;
  chainIntegrityVerified: boolean;
  globalMerkleRoot: string;
  topAttackerIps: Record<string, number>;
  topAttackedEndpoints: Record<string, number>;
  mitreTechniquesSummary: Record<string, number>;
  lastUpdatedUtc: string;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: 'AttackerIp' | 'TargetAsset' | 'MitreTechnique' | 'Application' | string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  value: number;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  relation: string;
  severity: string;
  count: number;
}

export interface AttackGraphData {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface PiiDetectionResult {
  piiType: string;
  matchedValueRedacted: string;
  confidenceScore: number;
}

export interface SecurityThreatAlert {
  threatType: string;
  description: string;
  severity: string;
  confidenceScore: number;
}

export interface TumLogEntry {
  logId: string;
  timestampUtc: string;
  eventName: string;
  category: number | string;
  severity: 'Trace' | 'Debug' | 'Information' | 'Warning' | 'Error' | 'Critical' | string;
  applicationName: string;
  environment: string;
  userId?: string;
  clientIp: string;
  requestPath?: string;
  httpMethod?: string;
  statusCode?: number;
  executionDurationMs: number;
  payloadSanitized: string;
  piiRedactedCount: number;
  redactedDetails: PiiDetectionResult[];
  securityThreats: SecurityThreatAlert[];
  tamperProofHash: string;
  previousEntryHash: string;
  merkleRoot: string;
  correlationId: string;
  standardAction?: string;
}

export interface EventQueryResult {
  queryExecuted: string;
  totalScanned: number;
  totalMatched: number;
  executionDurationMs: number;
  items: TumLogEntry[];
  translatedSqlWhere: string;
}

export interface IngestLogResponse {
  logId: string;
  tamperProofHash: string;
  merkleRoot: string;
  piiRedacted: number;
  riskScore: number;
  severityBand: string;
  sigmaMatchesCount: number;
  timestampUtc: string;
}

export interface ComplianceAuditSummary {
  certificationId: string;
  standardName: string;
  computerCrimeActSec26Compliant: boolean;
  thaiPdpaCompliant: boolean;
  iso27001Compliant: boolean;
  ntpStratum1Synchronized: boolean;
  ntpServerHost: string;
  immutableWormChainHead: string;
  globalMerkleRoot: string;
  wormRetentionDaysEnforced: number;
  totalAuditedEvents: number;
  totalPiiRedactedElements: number;
  chainIntegrityCryptographicallyVerified: boolean;
  reportGeneratedUtc: string;
}

export interface SigmaRulesSummary {
  activeRuleCount: number;
}

export interface RegisterSigmaRuleResult {
  message: string;
  ruleId: string;
  title: string;
}
