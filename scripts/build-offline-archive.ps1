# TUM-OpenSIEM Offline Container Archive Builder
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$socsRoot = Resolve-Path (Join-Path $scriptDir "..\..\..\tum-socs")
$stagingDir = Join-Path $scriptDir ".appliance_staging"

Write-Host "Creating staging directory: $stagingDir" -ForegroundColor Cyan
if (Test-Path $stagingDir) {
    Remove-Item -Recurse -Force $stagingDir
}
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir "clickhouse") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir "rules") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir "server") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stagingDir "web") | Out-Null

# Copy Docker manifests
Copy-Item (Join-Path $scriptDir "Dockerfile") $stagingDir
Copy-Item (Join-Path $scriptDir "docker-compose.yml") $stagingDir

# Copy SigmaHQ detection rules
Copy-Item -Recurse (Join-Path $socsRoot "rules\*") (Join-Path $stagingDir "rules")

# Copy compiled Linux x64 server runtime
Copy-Item (Join-Path $socsRoot "dist\linux-x64\Tum.Siem.Server") (Join-Path $stagingDir "server")
Copy-Item (Join-Path $socsRoot "dist\linux-x64\appsettings.json") (Join-Path $stagingDir "server")
Copy-Item -Recurse (Join-Path $socsRoot "dist\linux-x64\wwwroot") (Join-Path $stagingDir "server")

# Copy Hallmark Console Web HUD
Copy-Item (Join-Path $socsRoot "visualizers\index.html") (Join-Path $stagingDir "web\hallmark-console.html")

# ClickHouse schema initialization script
$initSchemaSql = @"
CREATE DATABASE IF NOT EXISTS tum_siem;

CREATE TABLE IF NOT EXISTS tum_siem.security_events (
    log_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    category LowCardinality(String),
    severity LowCardinality(String),
    application_name LowCardinality(String),
    environment LowCardinality(String),
    user_id Nullable(String),
    client_ip String,
    request_path Nullable(String),
    http_method LowCardinality(Nullable(String)),
    status_code Nullable(Int32),
    execution_duration_ms Float64,
    payload_sanitized String,
    pii_redacted_count UInt32,
    tamper_proof_hash FixedString(64),
    previous_entry_hash FixedString(64),
    merkle_root FixedString(64),
    correlation_id String,
    standard_action LowCardinality(String),
    defense_mode LowCardinality(String),
    compliance_flags UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, category, severity, application_name);
"@
$initSchemaSql | Out-File -FilePath (Join-Path $stagingDir "clickhouse\init-schema.sql") -Encoding utf8

# ClickHouse sink options
$clickhouseConfig = @"
{
  "ClickHouseSink": {
    "IsEnabled": true,
    "EndpointUri": "http://clickhouse:8123",
    "Database": "tum_siem",
    "TableName": "security_events",
    "Username": "tum_admin",
    "Password": "tum_sovereign_2026",
    "AutoCreateSchema": true,
    "BatchSize": 10000,
    "FlushIntervalMs": 500,
    "MaxBufferCapacity": 500000
  }
}
"@
$clickhouseConfig | Out-File -FilePath (Join-Path $stagingDir "clickhouse\clickhouse-sink-config.json") -Encoding utf8

# Package manifest
$manifestJson = @"
{
  "name": "tum-opensiem-appliance-offline",
  "version": "2.0.0",
  "releaseDate": "2026-11-09T16:55:00Z",
  "description": "TUM-OpenSIEM All-in-One Enterprise Appliance Container Offline Bundle",
  "components": {
    "tum-siem-appliance": {
      "image": "tum-trust/tum-opensiem:2.0.0",
      "runtime": "dotnet-8.0-aspnet-alpine",
      "ports": ["5200:5200", "514:514/udp", "514:514/tcp"],
      "binary": "server/Tum.Siem.Server"
    },
    "clickhouse-sink": {
      "image": "clickhouse/clickhouse-server:24.3-alpine",
      "ports": ["8123:8123", "9000:9000"],
      "database": "tum_siem",
      "table": "security_events"
    }
  },
  "sigmaRulesCount": 6,
  "hallmarkConsoleWeb": "web/hallmark-console.html"
}
"@
$manifestJson | Out-File -FilePath (Join-Path $stagingDir "manifest.json") -Encoding utf8

$targetArchive = Join-Path $scriptDir "tum-opensiem-appliance-offline.tar.gz"
Write-Host "Compressing offline appliance archive with bsdtar -> $targetArchive" -ForegroundColor Cyan

# Use bsdtar to create tar.gz
Set-Location $scriptDir
& tar -czvf $targetArchive -C $stagingDir .

if (Test-Path $targetArchive) {
    $archiveSizeMb = [math]::Round((Get-Item $targetArchive).Length / 1MB, 2)
    Write-Host "[SUCCESS] Created offline archive: $targetArchive ($archiveSizeMb MB)" -ForegroundColor Green
    Remove-Item -Recurse -Force $stagingDir
} else {
    Write-Host "[ERROR] Failed to generate $targetArchive" -ForegroundColor Red
    exit 1
}
