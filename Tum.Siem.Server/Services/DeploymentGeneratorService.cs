// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.IO.Compression;
using System.Text;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;

namespace Tum.Siem.Server.Services;

public sealed class DeploymentGeneratorService : IDeploymentGeneratorService
{
    public DeploymentBundleResponse GenerateBundle(DeploymentConfigDto config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config.Tier switch
        {
            ArchitectureTier.SingleNodeLab => GenerateSingleNodeBundle(config),
            ArchitectureTier.EnterpriseCluster => GenerateEnterpriseClusterBundle(config),
            ArchitectureTier.NationalFlashCrowd => GenerateNationalFlashCrowdBundle(config),
            _ => GenerateSingleNodeBundle(config)
        };
    }

    public async Task<byte[]> GenerateZipArchiveAsync(DeploymentConfigDto config)
    {
        var bundle = GenerateBundle(config);

        using var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true))
        {
            foreach (var file in bundle.Files)
            {
                var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal);
                await using var entryStream = entry.Open();
                await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
                await writer.WriteAsync(file.Content);
            }
        }

        return memoryStream.ToArray();
    }

    private static DeploymentBundleResponse GenerateSingleNodeBundle(DeploymentConfigDto c)
    {
        var files = new List<DeploymentFileDto>();

        // 1. docker-compose.yml
        string compose = $@"# ==============================================================================
# TUM-OpenSIEM Single-Node Appliance Deployment
# Architecture: Single-Node Lab / Small Branch Office (< 5,000 EPS)
# ==============================================================================

version: '3.8'

networks:
  tum-mesh:
    name: tum-enterprise-mesh
    driver: bridge

services:
  clickhouse:
    image: clickhouse/clickhouse-server:24.3-alpine
    container_name: tum-clickhouse-sink
    hostname: clickhouse
    networks:
      - tum-mesh
    ports:
      - ""8123:8123"" # HTTP Query Interface
      - ""9000:9000"" # Native TCP Interface
    environment:
      - CLICKHOUSE_DB=tum_siem
      - CLICKHOUSE_USER=tum_admin
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
      - CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - clickhouse_logs:/var/log/clickhouse-server
      - ./init-clickhouse.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: [""CMD-SHELL"", ""wget --no-verbose --tries=1 --spider http://localhost:8123/ping || exit 1""]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 262144
        hard: 262144

  tum-siem-appliance:
    image: tum-trust/tum-opensiem:2.0.0
    container_name: tum-siem-appliance
    hostname: {c.DomainName.Split('.')[0]}
    networks:
      - tum-mesh
    ports:
      - ""{c.HttpPort}:5200""         # Hallmark Console Web HUD & REST Ingestion API
      - ""{c.SyslogUdpPort}:514/udp"" # Syslog RFC 5424/3164 (UDP)
      - ""{c.SyslogTcpPort}:514/tcp"" # Syslog RFC 5424/3164 (TCP)
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:5200
      - CLICKHOUSE_ENDPOINT=http://clickhouse:8123
      - CLICKHOUSE_DATABASE=tum_siem
      - CLICKHOUSE_USER=tum_admin
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
      - TUM_WORM_RETENTION_DAYS={c.WormRetentionDays}
      - TUM_NTP_SERVER_HOST={c.NtpServerHost}
      - TUM_RISK_THRESHOLD=70.0
      - TUM_DEFENSE_MODE=ActiveMitigation
      - TZ=Asia/Bangkok
    volumes:
      - tum_worm_storage:/app/tum_logs
      - ./rules:/app/rules:ro
    depends_on:
      clickhouse:
        condition: service_healthy
    healthcheck:
      test: [""CMD-SHELL"", ""wget -qO- http://localhost:5200/health || exit 1""]
      interval: 10s
      timeout: 3s
      retries: 3
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 65536
        hard: 65536

volumes:
  clickhouse_data:
    name: tum_siem_clickhouse_data
  clickhouse_logs:
    name: tum_siem_clickhouse_logs
  tum_worm_storage:
    name: tum_siem_worm_storage
";
        files.Add(new DeploymentFileDto
        {
            Path = "docker-compose.yml",
            Language = "yaml",
            Description = "Single-node Docker Compose specification for OpenSIEM and ClickHouse",
            Content = compose
        });

        // 2. .env
        string env = $@"# TUM-OpenSIEM Environment Configuration
SIEM_DOMAIN={c.DomainName}
SIEM_HTTP_PORT={c.HttpPort}
SIEM_SYSLOG_UDP={c.SyslogUdpPort}
SIEM_SYSLOG_TCP={c.SyslogTcpPort}
CLICKHOUSE_PASSWORD={c.ClickHousePassword}
WORM_RETENTION_DAYS={c.WormRetentionDays}
NTP_SERVER={c.NtpServerHost}
";
        files.Add(new DeploymentFileDto
        {
            Path = ".env",
            Language = "ini",
            Description = "Environment variable definitions",
            Content = env
        });

        // 3. init-clickhouse.sql
        string sql = @"-- TUM-OpenSIEM Core Telemetry Table DDL (ReplacingMergeTree)
CREATE DATABASE IF NOT EXISTS tum_siem;

CREATE TABLE IF NOT EXISTS tum_siem.tum_events (
    log_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    category LowCardinality(String),
    severity LowCardinality(String),
    application_name LowCardinality(String),
    environment LowCardinality(String),
    user_id Nullable(String),
    client_ip IPv4,
    request_path String,
    http_method LowCardinality(String),
    status_code Nullable(UInt16),
    execution_duration_ms Float32,
    risk_score Float32,
    tamper_proof_hash FixedString(64),
    merkle_root FixedString(64),
    pii_redacted_count UInt32,
    matched_rules Array(String),
    raw_payload String
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (category, timestamp, log_id)
SETTINGS index_granularity = 8192;
";
        files.Add(new DeploymentFileDto
        {
            Path = "init-clickhouse.sql",
            Language = "sql",
            Description = "ClickHouse schema initialization with fast columnar indexing",
            Content = sql
        });

        // 4. start.sh
        string sh = @"#!/usr/bin/env bash
set -euo pipefail

echo ""[+] Verifying Docker and Docker Compose prerequisites...""
command -v docker >/dev/null 2>&1 || { echo ""[-] Docker not installed. Aborting.""; exit 1; }

echo ""[+] Pulling container images...""
docker compose pull

echo ""[+] Launching TUM-OpenSIEM Appliance...""
docker compose up -d

echo ""[+] Waiting for SIEM Health Check...""
until docker compose ps | grep -q ""healthy""; do
    sleep 2
    echo -n "".""
done

echo """"
echo ""==================================================================""
echo ""  TUM-OpenSIEM Single-Node Appliance is ONLINE!""
echo ""  Web HUD: http://localhost:""${SIEM_HTTP_PORT:-5200}
echo ""  API Doc: http://localhost:""${SIEM_HTTP_PORT:-5200}""/swagger""
echo ""==================================================================""
";
        files.Add(new DeploymentFileDto
        {
            Path = "start.sh",
            Language = "shell",
            Description = "Automated Linux startup launcher script",
            Content = sh
        });

        // 5. README.md
        string readme = $@"# TUM-OpenSIEM Deployment Package (Single-Node Lab)

**Scale Tier:** Single-Node Lab (< 5,000 EPS)  
**Target Domain:** `{c.DomainName}`  
**CCA Sec 26 Retention:** {c.WormRetentionDays} Days  

## Quick Start
```bash
chmod +x start.sh
./start.sh
```

Access the Web Console at `http://localhost:{c.HttpPort}`.
";
        files.Add(new DeploymentFileDto
        {
            Path = "README.md",
            Language = "markdown",
            Description = "Deployment documentation and setup steps",
            Content = readme
        });

        return new DeploymentBundleResponse
        {
            Tier = ArchitectureTier.SingleNodeLab,
            TierName = "Single-Node Lab (< 5,000 EPS)",
            TargetScenario = "Small government agency, regional branch office, staging lab, or local developer testing.",
            Hardware = new HardwareRecommendationDto
            {
                MinCpu = "4 Cores (x86_64 / ARM64)",
                MinRam = "8 GB",
                StorageType = "Standard SSD (>= 500 IOPS)",
                NetworkBandwidth = "1 Gbps",
                MaxSustainedEps = "5,000 EPS",
                PeakConcurrencyUsers = "1,000 Concurrent Users"
            },
            Files = files,
            QuickStartCommand = "docker compose up -d",
            OneLineInstallScript = $"curl -fsSL https://{c.DomainName}/api/deployment/install.sh | bash"
        };
    }

    private static DeploymentBundleResponse GenerateEnterpriseClusterBundle(DeploymentConfigDto c)
    {
        var files = new List<DeploymentFileDto>();

        string compose = $@"# ==============================================================================
# TUM-OpenSIEM Enterprise Clustered Deployment
# Architecture: High-Throughput Redpanda Streaming Queue + Multi-Worker (5k - 50k EPS)
# ==============================================================================

version: '3.8'

networks:
  tum-cluster-mesh:
    name: tum-cluster-mesh
    driver: bridge

services:
  # 1. Redpanda Streaming Queue Buffer (Kafka-compatible, C++ lock-free, zero JVM overhead)
  redpanda:
    image: docker.redpanda.com/redpandadata/redpanda:v24.1.2
    container_name: tum-redpanda-buffer
    hostname: redpanda
    networks:
      - tum-cluster-mesh
    command:
      - redpanda
      - start
      - --smp 2
      - --memory 4G
      - --reserve-memory 0M
      - --overprovisioned
      - --node-id 0
      - --check=false
      - --kafka-addr PLAINTEXT://0.0.0.0:9092
      - --advertise-kafka-addr PLAINTEXT://redpanda:9092
    ports:
      - ""9092:9092""
    volumes:
      - redpanda_data:/var/lib/redpanda/data
    healthcheck:
      test: [""CMD-SHELL"", ""rpk cluster health | grep -q 'Healthy:.*true' || exit 1""]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  # 2. ClickHouse High-Performance Analytical Telemetry Sink
  clickhouse:
    image: clickhouse/clickhouse-server:24.3-alpine
    container_name: tum-clickhouse-sink
    hostname: clickhouse
    networks:
      - tum-cluster-mesh
    ports:
      - ""8123:8123""
      - ""9000:9000""
    environment:
      - CLICKHOUSE_DB=tum_siem
      - CLICKHOUSE_USER=tum_admin
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
      - CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - clickhouse_logs:/var/log/clickhouse-server
      - ./init-clickhouse.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: [""CMD-SHELL"", ""wget --no-verbose --tries=1 --spider http://localhost:8123/ping || exit 1""]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 262144
        hard: 262144

  # 3. Redis In-Memory State & Rate Limiting Cache
  redis:
    image: redis:7.2-alpine
    container_name: tum-siem-cache
    hostname: redis
    networks:
      - tum-cluster-mesh
    ports:
      - ""6379:6379""
    command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru --save """"
    restart: unless-stopped

  # 4. OpenSIEM Ingestion Gateway & Hallmark Web Console
  tum-siem-gateway:
    image: tum-trust/tum-opensiem:2.0.0
    container_name: tum-siem-gateway
    hostname: {c.DomainName.Split('.')[0]}
    networks:
      - tum-cluster-mesh
    ports:
      - ""{c.HttpPort}:5200""
      - ""{c.SyslogUdpPort}:514/udp""
      - ""{c.SyslogTcpPort}:514/tcp""
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:5200
      - CLICKHOUSE_ENDPOINT=http://clickhouse:8123
      - CLICKHOUSE_DATABASE=tum_siem
      - CLICKHOUSE_USER=tum_admin
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
      - KAFKA_BOOTSTRAP_SERVERS=redpanda:9092
      - REDIS_ENDPOINT=redis:6379
      - TUM_WORM_RETENTION_DAYS={c.WormRetentionDays}
      - TUM_NTP_SERVER_HOST={c.NtpServerHost}
      - TUM_SURGE_GOVERNOR_ENABLED=true
      - TUM_SURGE_THRESHOLD_EPS=10000
      - TZ=Asia/Bangkok
    volumes:
      - tum_worm_storage:/app/tum_logs
      - ./rules:/app/rules:ro
    depends_on:
      redpanda:
        condition: service_healthy
      clickhouse:
        condition: service_healthy
    restart: unless-stopped

  # 5. Dedicated Ingestion Worker 1 (Scalable Sigma Evaluation Engine)
  tum-siem-worker-1:
    image: tum-trust/tum-opensiem:2.0.0
    container_name: tum-siem-worker-1
    networks:
      - tum-cluster-mesh
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - SIEM_ROLE=Worker
      - KAFKA_BOOTSTRAP_SERVERS=redpanda:9092
      - CLICKHOUSE_ENDPOINT=http://clickhouse:8123
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
    volumes:
      - ./rules:/app/rules:ro
    depends_on:
      - redpanda
      - clickhouse
    restart: unless-stopped

  # 6. Dedicated Ingestion Worker 2 (Scalable Sigma Evaluation Engine)
  tum-siem-worker-2:
    image: tum-trust/tum-opensiem:2.0.0
    container_name: tum-siem-worker-2
    networks:
      - tum-cluster-mesh
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - SIEM_ROLE=Worker
      - KAFKA_BOOTSTRAP_SERVERS=redpanda:9092
      - CLICKHOUSE_ENDPOINT=http://clickhouse:8123
      - CLICKHOUSE_PASSWORD={c.ClickHousePassword}
    volumes:
      - ./rules:/app/rules:ro
    depends_on:
      - redpanda
      - clickhouse
    restart: unless-stopped

volumes:
  redpanda_data:
    name: tum_siem_redpanda_data
  clickhouse_data:
    name: tum_siem_clickhouse_cluster_data
  clickhouse_logs:
    name: tum_siem_clickhouse_cluster_logs
  tum_worm_storage:
    name: tum_siem_worm_cluster_storage
";
        files.Add(new DeploymentFileDto
        {
            Path = "docker-compose.enterprise.yml",
            Language = "yaml",
            Description = "Clustered Docker Compose with Redpanda streaming buffer and parallel worker fleet",
            Content = compose
        });

        // Linux OS sysctl tuning
        string sysctl = @"# Linux Kernel Network & High-Throughput Tuning (50,000 EPS)
# Place in /etc/sysctl.d/99-tum-siem.conf and run: sudo sysctl -p /etc/sysctl.d/99-tum-siem.conf

net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
fs.file-max = 2097152
vm.max_map_count = 262144
";
        files.Add(new DeploymentFileDto
        {
            Path = "sysctl-tuning.conf",
            Language = "ini",
            Description = "Linux kernel network socket and memory tuning for high-frequency packet ingestion",
            Content = sysctl
        });

        // ClickHouse table
        string sql = @"CREATE DATABASE IF NOT EXISTS tum_siem;

CREATE TABLE IF NOT EXISTS tum_siem.tum_events (
    log_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    category LowCardinality(String),
    severity LowCardinality(String),
    application_name LowCardinality(String),
    environment LowCardinality(String),
    user_id Nullable(String),
    client_ip IPv4,
    request_path String,
    http_method LowCardinality(String),
    status_code Nullable(UInt16),
    execution_duration_ms Float32,
    risk_score Float32,
    tamper_proof_hash FixedString(64),
    merkle_root FixedString(64),
    pii_redacted_count UInt32,
    matched_rules Array(String),
    raw_payload String
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (category, timestamp, log_id)
SETTINGS index_granularity = 8192;
";
        files.Add(new DeploymentFileDto
        {
            Path = "init-clickhouse.sql",
            Language = "sql",
            Description = "ClickHouse schema DDL",
            Content = sql
        });

        // start.sh
        string sh = @"#!/usr/bin/env bash
set -euo pipefail

echo ""[+] Checking Enterprise System Limits...""
sysctl -q vm.max_map_count || echo ""[!] Recommendation: Apply sysctl-tuning.conf for >50k EPS""

echo ""[+] Pulling Clustered Docker Images...""
docker compose -f docker-compose.enterprise.yml pull

echo ""[+] Starting Redpanda, ClickHouse, Redis, and OpenSIEM Cluster...""
docker compose -f docker-compose.enterprise.yml up -d

echo ""[+] Clustered Fleet successfully initiated!""
";
        files.Add(new DeploymentFileDto
        {
            Path = "start.sh",
            Language = "shell",
            Description = "Enterprise cluster bootstrap script",
            Content = sh
        });

        return new DeploymentBundleResponse
        {
            Tier = ArchitectureTier.EnterpriseCluster,
            TierName = "Enterprise Clustered Mesh (5,000 - 50,000 EPS)",
            TargetScenario = "Medium-to-large ministries, financial institutions, telecoms, and high-volume corporate SOCs.",
            Hardware = new HardwareRecommendationDto
            {
                MinCpu = "8 - 16 Cores (AMD EPYC / Intel Xeon)",
                MinRam = "32 GB DDR4/DDR5",
                StorageType = "NVMe PCIe 4.0 (>= 5,000 IOPS)",
                NetworkBandwidth = "10 Gbps",
                MaxSustainedEps = "50,000 EPS",
                PeakConcurrencyUsers = "25,000 Concurrent Users"
            },
            Files = files,
            QuickStartCommand = "docker compose -f docker-compose.enterprise.yml up -d",
            OneLineInstallScript = $"curl -fsSL https://{c.DomainName}/api/deployment/install.sh | bash"
        };
    }

    private static DeploymentBundleResponse GenerateNationalFlashCrowdBundle(DeploymentConfigDto c)
    {
        var files = new List<DeploymentFileDto>();

        // 1. values.yaml
        string valuesYaml = $@"# ==============================================================================
# TUM-OpenSIEM National Scale / Flash Crowd Helm Values
# Built for Mass Public Rushes (e.g. OCSC / ก.พ. 100k-300k Applicant Surges)
# Supported Throughput: > 100,000 EPS with Dynamic Smart In-Line Sampling
# ==============================================================================

replicaCount: {Math.Max(4, c.ReplicaCount)}

image:
  repository: tum-trust/tum-opensiem
  tag: ""2.0.0""
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  httpPort: 5200
  syslogUdpPort: {c.SyslogUdpPort}
  syslogTcpPort: {c.SyslogTcpPort}

ingress:
  enabled: true
  className: ""nginx""
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: ""64m""
    nginx.ingress.kubernetes.io/proxy-buffering: ""on""
    nginx.ingress.kubernetes.io/proxy-buffers-number: ""8""
    nginx.ingress.kubernetes.io/proxy-buffer-size: ""16k""
    nginx.ingress.kubernetes.io/proxy-read-timeout: ""60""
    nginx.ingress.kubernetes.io/proxy-send-timeout: ""60""
    nginx.ingress.kubernetes.io/upstream-keepalive-connections: ""1000""
  hosts:
    - host: {c.DomainName}
      paths:
        - path: /
          pathType: Prefix

resources:
  limits:
    cpu: 8000m
    memory: 16Gi
  requests:
    cpu: 2000m
    memory: 4Gi

autoscaling:
  enabled: true
  minReplicas: 4
  maxReplicas: 24
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 75

persistence:
  enabled: true
  storageClass: ""fast-nvme""
  size: {c.StorageSizeGb}Gi
  mountPath: /app/tum_logs

siemConfig:
  environment: Production
  alertRiskThreshold: 70.0
  enableAutoPiiMasking: true
  enableThreatDetection: true
  enableMerkleChaining: true
  wormRetentionDays: {c.WormRetentionDays}
  ntpServerHost: ""{c.NtpServerHost}""

# Flash Crowd Surge Governor
surgeGovernor:
  enabled: {c.EnableSmartSamplingSurge.ToString().ToLowerInvariant()}
  surgeThresholdEps: 10000
  benignSampleRate: 50
  forceSurgeMode: false

# Clustered ClickHouse Backend
clickhouse:
  enabled: true
  image:
    repository: clickhouse/clickhouse-server
    tag: ""24.3-alpine""
  database: tum_siem
  user: tum_admin
  password: ""{c.ClickHousePassword}""
  persistence:
    size: ""1000Gi""
    storageClass: ""fast-nvme""
  resources:
    limits:
      cpu: 16000m
      memory: {c.ClickHouseMemoryLimit}
    requests:
      cpu: 4000m
      memory: 8Gi
";
        files.Add(new DeploymentFileDto
        {
            Path = "helm-values.yaml",
            Language = "yaml",
            Description = "Production Helm chart values for high-concurrency Kubernetes cluster",
            Content = valuesYaml
        });

        // 2. keda-autoscaler.yaml
        string keda = @"# ==============================================================================
# KEDA (Kubernetes Event-driven Autoscaling) ScaledObject
# Dynamically scales TUM-OpenSIEM Ingestion Pods from 4 to 24 replicas based on
# real-time EPS ingestion pressure and streaming buffer lag.
# ==============================================================================

apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: tum-opensiem-keda-autoscaler
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: tum-opensiem
  minReplicaCount: 4
  maxReplicaCount: 24
  cooldownPeriod: 30
  pollingInterval: 5
  triggers:
    # Trigger 1: Prometheus Real-time EPS Metric from OpenSIEM Internal Governor
    - type: prometheus
      metadata:
        serverAddress: http://prometheus-k8s.monitoring.svc:9090
        metricName: tum_siem_incoming_eps
        query: sum(rate(tum_siem_events_total[30s]))
        threshold: '8000' # Scale up another pod for every 8,000 EPS increment

    # Trigger 2: Kafka / Redpanda Consumer Group Lag
    - type: kafka
      metadata:
        bootstrapServers: redpanda.default.svc.cluster.local:9092
        consumerGroup: tum-opensiem-ingestion-workers
        topic: tum-security-telemetry
        lagThreshold: '10000' # If queue lag exceeds 10,000 items, scale immediately
";
        files.Add(new DeploymentFileDto
        {
            Path = "keda-autoscaler.yaml",
            Language = "yaml",
            Description = "KEDA queue-based and EPS-based real-time autoscaler manifest",
            Content = keda
        });

        // 3. surge-governor.json
        string governorJson = @"{
  ""surgeGovernor"": {
    ""enabled"": true,
    ""surgeThresholdEps"": 10000,
    ""benignSampleRate"": 50,
    ""guaranteedForensicRetention"": [
      ""HTTP_STATUS_4XX"",
      ""HTTP_STATUS_5XX"",
      ""SECURITY_THREAT"",
      ""AUDIT_TRAIL"",
      ""PII_ACCESS"",
      ""LEGAL_COMPLIANCE"",
      ""AUTH_LOGIN_EVENTS"",
      ""ADMIN_MUTATIONS"",
      ""SIGMA_RULE_MATCHES""
    ],
    ""benignNoiseEligibleForSampling"": [
      ""HTTP_200_GET_STATIC_ASSETS"",
      ""HEALTH_CHECK_POLLING"",
      ""ROUTINE_HEARTBEATS""
    ]
  }
}";
        files.Add(new DeploymentFileDto
        {
            Path = "surge-governor.json",
            Language = "json",
            Description = "Application-layer Smart Sampling Governor rules for flash crowd mitigation",
            Content = governorJson
        });

        // 4. clickhouse-cluster.sql
        string chCluster = @"-- ClickHouse Distributed Cluster DDL with ReplicatedReplacingMergeTree
CREATE DATABASE IF NOT EXISTS tum_siem ON CLUSTER '{cluster}';

CREATE TABLE IF NOT EXISTS tum_siem.tum_events_local ON CLUSTER '{cluster}' (
    log_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    category LowCardinality(String),
    severity LowCardinality(String),
    application_name LowCardinality(String),
    environment LowCardinality(String),
    user_id Nullable(String),
    client_ip IPv4,
    request_path String,
    http_method LowCardinality(String),
    status_code Nullable(UInt16),
    execution_duration_ms Float32,
    risk_score Float32,
    tamper_proof_hash FixedString(64),
    merkle_root FixedString(64),
    pii_redacted_count UInt32,
    matched_rules Array(String),
    raw_payload String
) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/tum_events', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (category, timestamp, log_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS tum_siem.tum_events ON CLUSTER '{cluster}' AS tum_siem.tum_events_local
ENGINE = Distributed('{cluster}', tum_siem, tum_events_local, rand());
";
        files.Add(new DeploymentFileDto
        {
            Path = "clickhouse-cluster.sql",
            Language = "sql",
            Description = "Distributed ClickHouse sharded schema DDL",
            Content = chCluster
        });

        // 5. deploy-k8s.sh
        string k8sSh = @"#!/usr/bin/env bash
set -euo pipefail

echo ""[+] Validating Kubernetes Cluster Connection...""
kubectl cluster-info >/dev/null 2>&1 || { echo ""[-] Cannot connect to Kubernetes cluster.""; exit 1; }

echo ""[+] Installing or Upgrading TUM-OpenSIEM via Helm...""
helm upgrade --install tum-opensiem ./tum-opensiem \
  --values helm-values.yaml \
  --namespace security \
  --create-namespace

echo ""[+] Applying KEDA Autoscaler...""
kubectl apply -f keda-autoscaler.yaml --namespace security

echo ""[+] Deployment complete! Checking Pods...""
kubectl get pods -n security -l app.kubernetes.io/name=tum-opensiem
";
        files.Add(new DeploymentFileDto
        {
            Path = "deploy-k8s.sh",
            Language = "shell",
            Description = "Turnkey Kubernetes Helm and KEDA deployment automation script",
            Content = k8sSh
        });

        // 6. README.md
        string readme = $@"# TUM-OpenSIEM National-Scale Flash Crowd Architecture

**Scale Tier:** National / Flash Crowd (> 100,000 EPS)  
**Target Scenario:** National portal registration surges (e.g. OCSC / ก.พ. 100k-300k concurrent users)  
**Retention Compliance:** {c.WormRetentionDays} Days (Thai CCA Sec 26 & PDPA)  

## Key Architectural Protections
1. **Queue-Based Decoupling:** Redpanda/Kafka absorbs surges up to 300,000 EPS without dropping packets.
2. **KEDA Auto-Scaling:** Automatically scales SIEM pods from 4 to 24 replicas within 15 seconds.
3. **Smart In-Line Sampling:** Samples benign HTTP 200 GET noise while guaranteeing 100% forensic retention for all security, authentication, and error events.
";
        files.Add(new DeploymentFileDto
        {
            Path = "README.md",
            Language = "markdown",
            Description = "National scale deployment architectural manual",
            Content = readme
        });

        return new DeploymentBundleResponse
        {
            Tier = ArchitectureTier.NationalFlashCrowd,
            TierName = "National Scale & Flash Crowd (> 100,000 EPS)",
            TargetScenario = "National public services, exam registration portals (OCSC / ก.พ.), mass voting, central bank switchboards.",
            Hardware = new HardwareRecommendationDto
            {
                MinCpu = "Kubernetes Cluster (3 Control, 6+ Worker Nodes, 64+ Cores Total)",
                MinRam = "128 GB Cluster Memory",
                StorageType = "Distributed Ceph / Cloud NVMe (>= 20,000 IOPS)",
                NetworkBandwidth = "25 Gbps Fabric",
                MaxSustainedEps = "> 150,000 EPS",
                PeakConcurrencyUsers = "100,000 - 300,000 Concurrent Users"
            },
            Files = files,
            QuickStartCommand = "helm upgrade --install tum-opensiem ./tum-opensiem -f helm-values.yaml",
            OneLineInstallScript = $"curl -fsSL https://{c.DomainName}/api/deployment/install-k8s.sh | bash"
        };
    }
}
