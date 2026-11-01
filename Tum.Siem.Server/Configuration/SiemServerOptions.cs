// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.Configuration;

/// <summary>
/// Strongly-typed configuration options for the TUM OpenSIEM Server.
/// </summary>
public sealed class SiemServerOptions
{
    public const string SectionName = "Siem";

    public string ApplicationName { get; set; } = "TUM-OpenSIEM-Core";
    public string Environment { get; set; } = "Production";
    public bool EnableAutoPiiMasking { get; set; } = true;
    public bool EnableThreatDetection { get; set; } = true;
    public bool EnableMerkleChaining { get; set; } = true;
    public int WormRetentionDays { get; set; } = 90;
    public string StorageDirectory { get; set; } = "tum_logs";
    public string RulesDirectory { get; set; } = "rules";
    public double AlertRiskThreshold { get; set; } = 70.0;
    public string NtpServerHost { get; set; } = "time.navy.mi.th";
    public string[] CorsOrigins { get; set; } = ["*"];
}
