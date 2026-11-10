// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.Models;

public enum CloudProviderType
{
    Kubernetes = 1,
    AwsEc2 = 2,
    LinuxSshHost = 3,
    LocalEmulated = 4
}

public enum NodeHealthStatus
{
    Healthy = 1,
    Warning = 2,
    Critical = 3,
    Offline = 4
}

public sealed record CloudScaleRequest
{
    public CloudProviderType Provider { get; init; } = CloudProviderType.Kubernetes;
    public string TargetClusterOrHost { get; init; } = "default-cluster";
    public string Namespace { get; init; } = "default";
    public string TargetDeploymentName { get; init; } = "tum-opensiem";
    public int DesiredReplicas { get; init; } = 4;
    public string InstanceType { get; init; } = "c6i.4xlarge";
    public Dictionary<string, string> Parameters { get; init; } = new();
}

public sealed record CloudScaleResult
{
    public bool Success { get; init; }
    public CloudProviderType Provider { get; init; }
    public string TargetName { get; init; } = string.Empty;
    public int PreviousReplicas { get; init; }
    public int CurrentReplicas { get; init; }
    public string Message { get; init; } = string.Empty;
    public DateTimeOffset ExecutedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string ProviderAttribution { get; init; } = "[SYSTEM]";
}

public sealed record HostCommandRequest
{
    public string NodeId { get; init; } = string.Empty;
    public string Command { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; } = 15;
}

public sealed record HostCommandResult
{
    public bool Success { get; init; }
    public string NodeId { get; init; } = string.Empty;
    public int ExitCode { get; init; }
    public string StandardOutput { get; init; } = string.Empty;
    public string StandardError { get; init; } = string.Empty;
    public double ExecutionDurationMs { get; init; }
}

public sealed record DiskMetrics
{
    public string MountPoint { get; init; } = "/";
    public long TotalBytes { get; init; }
    public long FreeBytes { get; init; }
    public double UsagePercent => TotalBytes > 0
        ? Math.Round((double)(TotalBytes - FreeBytes) / TotalBytes * 100.0, 1)
        : 0.0;
    public double ReadIops { get; init; }
    public double WriteIops { get; init; }
}

public sealed record HostNodeMetrics
{
    public string NodeId { get; init; } = Guid.NewGuid().ToString("N");
    public string Hostname { get; init; } = Environment.MachineName;
    public string IpAddress { get; init; } = "127.0.0.1";
    public string OsDescription { get; init; } = Environment.OSVersion.ToString();
    public int CpuCoreCount { get; init; } = Environment.ProcessorCount;
    public double CpuUsagePercent { get; init; }
    public long TotalMemoryBytes { get; init; }
    public long UsedMemoryBytes { get; init; }
    public long AvailableMemoryBytes { get; init; }
    public double MemoryUsagePercent => TotalMemoryBytes > 0
        ? Math.Round((double)UsedMemoryBytes / TotalMemoryBytes * 100.0, 1)
        : 0.0;
    public List<DiskMetrics> Disks { get; init; } = new();
    public double InboundKbps { get; init; }
    public double OutboundKbps { get; init; }
    public int TcpEstablishedCount { get; init; }
    public int TcpTimeWaitCount { get; init; }
    public int TcpListenCount { get; init; }
    public NodeHealthStatus Status { get; init; } = NodeHealthStatus.Healthy;
    public DateTimeOffset LastHeartbeatUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record LoadTestScenario
{
    public int TargetEps { get; init; } = 20_000;
    public int DurationSeconds { get; init; } = 10;
    public int RampUpSeconds { get; init; } = 3;
    public string TrafficProfile { get; init; } = "MixedSecurityAndWebTraffic";
}

public sealed record LoadTestRunResult
{
    public string TestId { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset StartedAtUtc { get; init; }
    public DateTimeOffset CompletedAtUtc { get; init; }
    public int TargetEps { get; init; }
    public double AchievedMaxEps { get; init; }
    public double AverageEps { get; init; }
    public long TotalEventsSent { get; init; }
    public long TotalEventsIngested { get; init; }
    public long TotalDropped { get; init; }
    public double LatencyP50Ms { get; init; }
    public double LatencyP90Ms { get; init; }
    public double LatencyP99Ms { get; init; }
    public double PeakCpuPercent { get; init; }
    public long PeakMemoryBytes { get; init; }
    public bool IsTargetSustained { get; init; }
    public string Verdict { get; init; } = "READY";
}

public sealed record InfraReadinessCertificate
{
    public string CertificateId { get; init; } = $"TUM-IRC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..8].ToUpperInvariant()}";
    public DateTimeOffset IssuedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string TargetSystemName { get; init; } = "TUM-OpenSIEM Core Fleet";
    public string EvaluationVerdict { get; init; } = "READY_FOR_NATIONAL_FLASH_CROWD";
    public double TestedThroughputEps { get; init; }
    public int EstimatedConcurrentCapacity { get; init; }
    public double LatencyP99Ms { get; init; }
    public double StorageIopsCapacity { get; init; }
    public IReadOnlyList<string> VerifiedCapabilities { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Recommendations { get; init; } = Array.Empty<string>();
    public string CryptographicAttestationHash { get; init; } = string.Empty;
}
