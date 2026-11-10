// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Result of evaluating an incoming telemetry log against the Flash Crowd & Surge Governor.
/// </summary>
public sealed record SamplingDecision
{
    /// <summary>
    /// If true, the event is redundant benign noise during a high-throughput surge and should be dropped/sampled out.
    /// </summary>
    public bool ShouldSampleOut { get; init; }

    /// <summary>
    /// If true, the event is classified as critical security/forensic evidence and is guaranteed 100% retention.
    /// </summary>
    public bool IsCriticalSecurity { get; init; }

    /// <summary>
    /// Effective statistical weight for the sample (1 if not sampled, or N during surge sampling).
    /// </summary>
    public int SampleWeight { get; init; } = 1;

    /// <summary>
    /// Human-readable explanation of the governor's decision.
    /// </summary>
    public string Reason { get; init; } = string.Empty;
}

/// <summary>
/// Telemetry statistics from the Flash Crowd & Surge Governor.
/// </summary>
public sealed record GovernorStats
{
    public long CurrentEps { get; init; }
    public bool IsSurgeActive { get; init; }
    public bool ForceSurgeMode { get; init; }
    public int SurgeThresholdEps { get; init; }
    public int BenignSampleRate { get; init; }
    public long TotalProcessed { get; init; }
    public long TotalRetained { get; init; }
    public long TotalSampledOut { get; init; }
    public long TotalCriticalRetained { get; init; }
    public double IngestionLoadReductionPercent => TotalProcessed > 0
        ? Math.Round((double)TotalSampledOut / TotalProcessed * 100.0, 1)
        : 0.0;
}

/// <summary>
/// Interface for application-level smart sampling and surge protection during mass user rushes (e.g. OCSC / ก.พ. 100k-300k exam rush).
/// </summary>
public interface ISmartSamplingGovernor
{
    /// <summary>
    /// Evaluates an incoming log entry to determine if it must be retained or sampled.
    /// </summary>
    SamplingDecision Evaluate(TumLogEntry entry);

    /// <summary>
    /// Retrieves current operational metrics and surge status.
    /// </summary>
    GovernorStats GetStats();

    /// <summary>
    /// Dynamically updates governor configuration and force-surge flag.
    /// </summary>
    void Configure(bool? forceSurge, int? surgeThresholdEps, int? benignSampleRate);
}
