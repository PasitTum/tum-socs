// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Production Smart Sampling & Flash Crowd Governor.
/// Protects OpenSIEM storage, CPU, and RingBuffer from catastrophic saturation during national-scale rushes
/// (e.g. OCSC / ก.พ. 100k-300k applicant rushes) by dynamically sampling benign repetitive polling (HTTP 200 GET, /health, static assets)
/// while guaranteeing 100% forensic and legal retention for all authentication, security, authorization, and error events.
/// </summary>
public sealed class SmartSamplingGovernor : ISmartSamplingGovernor
{
    private static readonly HashSet<string> SensitiveKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "login", "auth", "admin", "token", "password", "secret", "privilege", "credential",
        "sudoers", "mimikatz", "kerberos", "psexec", "injection", "jailbreak", "exfiltration",
        "wevtutil", "vssadmin", "tunneling", "brute", "deny", "block", "firewall", "4688", "4672", "4670", "1125"
    };

    private static readonly HashSet<string> BenignStaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"
    };

    private int _surgeThresholdEps = 10_000;
    private int _benignSampleRate = 20; // 1 out of 20 retained when in surge
    private bool _forceSurgeMode = false;

    // Sliding 1-second EPS calculation
    private long _currentEpochSecond;
    private long _eventsInCurrentSecond;
    private long _cachedEps;

    // Lifetime counters
    private long _totalProcessed;
    private long _totalRetained;
    private long _totalSampledOut;
    private long _totalCriticalRetained;
    private long _benignCounter;

    public SamplingDecision Evaluate(TumLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        Interlocked.Increment(ref _totalProcessed);
        UpdateEps();

        bool isSurgeActive = _forceSurgeMode || _cachedEps >= _surgeThresholdEps;

        // 1. Critical Forensic Checks: Guaranteed 100% Retention
        if (IsCritical(entry))
        {
            Interlocked.Increment(ref _totalRetained);
            Interlocked.Increment(ref _totalCriticalRetained);

            return new SamplingDecision
            {
                ShouldSampleOut = false,
                IsCriticalSecurity = true,
                SampleWeight = 1,
                Reason = "Guaranteed 100% Retention (Security/Auth/Compliance/Error Boundary)"
            };
        }

        // 2. If not in surge, keep 100% of benign telemetry
        if (!isSurgeActive)
        {
            Interlocked.Increment(ref _totalRetained);
            return new SamplingDecision
            {
                ShouldSampleOut = false,
                IsCriticalSecurity = false,
                SampleWeight = 1,
                Reason = "Normal Traffic Level (Under Surge Threshold)"
            };
        }

        // 3. Surge Active: Apply dynamic 1-in-N sampling to benign repetitive noise
        long count = Interlocked.Increment(ref _benignCounter);
        int rate = Math.Max(1, _benignSampleRate);

        if (count % rate == 0)
        {
            // The 1 sample kept to represent N requests for volumetric accuracy
            Interlocked.Increment(ref _totalRetained);
            return new SamplingDecision
            {
                ShouldSampleOut = false,
                IsCriticalSecurity = false,
                SampleWeight = rate,
                Reason = $"Surge Mitigation Active: Retained 1-in-{rate} sample for volumetric analytics"
            };
        }

        // Sampled out to protect storage and ingestion pipeline
        Interlocked.Increment(ref _totalSampledOut);
        return new SamplingDecision
        {
            ShouldSampleOut = true,
            IsCriticalSecurity = false,
            SampleWeight = rate,
            Reason = $"Surge Mitigation Active: Benign repetitive noise sampled out ({_cachedEps:N0} EPS)"
        };
    }

    public GovernorStats GetStats()
    {
        UpdateEps();
        bool isSurge = _forceSurgeMode || _cachedEps >= _surgeThresholdEps;

        return new GovernorStats
        {
            CurrentEps = _cachedEps,
            IsSurgeActive = isSurge,
            ForceSurgeMode = _forceSurgeMode,
            SurgeThresholdEps = _surgeThresholdEps,
            BenignSampleRate = _benignSampleRate,
            TotalProcessed = Interlocked.Read(ref _totalProcessed),
            TotalRetained = Interlocked.Read(ref _totalRetained),
            TotalSampledOut = Interlocked.Read(ref _totalSampledOut),
            TotalCriticalRetained = Interlocked.Read(ref _totalCriticalRetained)
        };
    }

    public void Configure(bool? forceSurge, int? surgeThresholdEps, int? benignSampleRate)
    {
        if (forceSurge.HasValue)
        {
            _forceSurgeMode = forceSurge.Value;
        }

        if (surgeThresholdEps.HasValue && surgeThresholdEps.Value > 0)
        {
            _surgeThresholdEps = surgeThresholdEps.Value;
        }

        if (benignSampleRate.HasValue && benignSampleRate.Value >= 1)
        {
            _benignSampleRate = benignSampleRate.Value;
        }
    }

    private bool IsCritical(TumLogEntry entry)
    {
        // 1. Any HTTP status code >= 400 (Client or Server Error) must never be sampled
        if (entry.StatusCode.HasValue && entry.StatusCode.Value >= 400)
        {
            return true;
        }

        // 2. High severity is never sampled
        if (!string.Equals(entry.Severity, "Information", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(entry.Severity, "Debug", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(entry.Severity, "Trace", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // 3. Security, Audit, Legal compliance, or PII categories are never sampled
        if (entry.Category == LogCategory.SecurityThreat ||
            entry.Category == LogCategory.AuditTrail ||
            entry.Category == LogCategory.LegalCompliance ||
            entry.Category == LogCategory.PiiAccess ||
            entry.Category == LogCategory.BusinessTransaction)
        {
            return true;
        }

        // 4. Sensitive keywords in EventName or RequestPath
        if (!string.IsNullOrEmpty(entry.EventName))
        {
            foreach (var kw in SensitiveKeywords)
            {
                if (entry.EventName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        if (!string.IsNullOrEmpty(entry.RequestPath))
        {
            if (entry.RequestPath.Contains("/api/auth", StringComparison.OrdinalIgnoreCase) ||
                entry.RequestPath.Contains("/login", StringComparison.OrdinalIgnoreCase) ||
                entry.RequestPath.Contains("/admin", StringComparison.OrdinalIgnoreCase) ||
                entry.RequestPath.Contains("/token", StringComparison.OrdinalIgnoreCase) ||
                entry.RequestPath.Contains("/payment", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Check if it's explicitly a static benign asset
            string path = entry.RequestPath;
            int qIndex = path.IndexOf('?');
            if (qIndex >= 0) path = path[..qIndex];

            foreach (var ext in BenignStaticExtensions)
            {
                if (path.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            if (path.Equals("/health", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/ping", StringComparison.OrdinalIgnoreCase) ||
                path.Equals("/favicon.ico", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // If category is SystemDiagnostic and HTTP method is GET with 200, it is benign
        if (entry.Category == LogCategory.SystemDiagnostic &&
            string.Equals(entry.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) &&
            (!entry.StatusCode.HasValue || entry.StatusCode.Value == 200))
        {
            return false;
        }

        return false;
    }

    private void UpdateEps()
    {
        long nowSecond = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long prevSecond = Interlocked.Read(ref _currentEpochSecond);

        if (nowSecond > prevSecond)
        {
            if (Interlocked.CompareExchange(ref _currentEpochSecond, nowSecond, prevSecond) == prevSecond)
            {
                long prevCount = Interlocked.Exchange(ref _eventsInCurrentSecond, 1);
                _cachedEps = prevCount;
                return;
            }
        }

        Interlocked.Increment(ref _eventsInCurrentSecond);
    }
}
