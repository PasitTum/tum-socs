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

export type ArchitectureTier = 1 | 2 | 3;

export interface DeploymentConfig {
  tier: ArchitectureTier;
  domainName: string;
  httpPort: number;
  syslogUdpPort: number;
  syslogTcpPort: number;
  wormRetentionDays: number;
  clickHousePassword: string;
  clickHouseMemoryLimit: string;
  enableRedpandaQueue: boolean;
  enableSmartSamplingSurge: boolean;
  replicaCount: number;
  storageSizeGb: number;
  ntpServerHost: string;
}

export interface DeploymentFile {
  path: string;
  language: string;
  description: string;
  content: string;
}

export interface HardwareRecommendation {
  minCpu: string;
  minRam: string;
  storageType: string;
  networkBandwidth: string;
  maxSustainedEps: string;
  peakConcurrencyUsers: string;
}

export interface DeploymentBundle {
  tier: ArchitectureTier;
  tierName: string;
  targetScenario: string;
  hardware: HardwareRecommendation;
  files: DeploymentFile[];
  quickStartCommand: string;
  oneLineInstallScript: string;
}

export interface GovernorStats {
  currentEps: number;
  isSurgeActive: boolean;
  forceSurgeMode: boolean;
  surgeThresholdEps: number;
  benignSampleRate: number;
  totalProcessed: number;
  totalRetained: number;
  totalSampledOut: number;
  totalCriticalRetained: number;
  ingestionLoadReductionPercent: number;
}

export interface DiskMetrics {
  mountPoint: string;
  totalBytes: number;
  freeBytes: number;
  usagePercent: number;
  readIops: number;
  writeIops: number;
}

export interface HostNodeMetrics {
  nodeId: string;
  hostname: string;
  ipAddress: string;
  osDescription: string;
  cpuCoreCount: number;
  cpuUsagePercent: number;
  totalMemoryBytes: number;
  usedMemoryBytes: number;
  availableMemoryBytes: number;
  memoryUsagePercent: number;
  disks: DiskMetrics[];
  inboundKbps: number;
  outboundKbps: number;
  tcpEstablishedCount: number;
  tcpTimeWaitCount: number;
  tcpListenCount: number;
  status: 1 | 2 | 3 | 4; // 1: Healthy, 2: Warning, 3: Critical, 4: Offline
  lastHeartbeatUtc: string;
}

export interface CloudScaleRequest {
  provider: 1 | 2 | 3 | 4; // 1: K8s, 2: AWS, 3: Linux, 4: Local
  targetClusterOrHost: string;
  namespace: string;
  targetDeploymentName: string;
  desiredReplicas: number;
  instanceType: string;
  parameters?: Record<string, string>;
}

export interface CloudScaleResult {
  success: boolean;
  provider: number;
  targetName: string;
  previousReplicas: number;
  currentReplicas: number;
  message: string;
  executedAtUtc: string;
  providerAttribution: string;
}

export interface HostCommandRequest {
  nodeId: string;
  command: string;
  timeoutSeconds: number;
}

export interface HostCommandResult {
  success: boolean;
  nodeId: string;
  exitCode: number;
  standardOutput: string;
  standardError: string;
  executionDurationMs: number;
}

export interface LoadTestScenario {
  targetEps: number;
  durationSeconds: number;
  rampUpSeconds: number;
  trafficProfile: string;
}

export interface LoadTestRunResult {
  testId: string;
  startedAtUtc: string;
  completedAtUtc: string;
  targetEps: number;
  achievedMaxEps: number;
  averageEps: number;
  totalEventsSent: number;
  totalEventsIngested: number;
  totalDropped: number;
  latencyP50Ms: number;
  latencyP90Ms: number;
  latencyP99Ms: number;
  peakCpuPercent: number;
  peakMemoryBytes: number;
  isTargetSustained: boolean;
  verdict: string;
}

export interface InfraReadinessCertificate {
  certificateId: string;
  issuedAtUtc: string;
  targetSystemName: string;
  evaluationVerdict: string;
  testedThroughputEps: number;
  estimatedConcurrentCapacity: number;
  latencyP99Ms: number;
  storageIopsCapacity: number;
  verifiedCapabilities: string[];
  recommendations: string[];
  cryptographicAttestationHash: string;
}

