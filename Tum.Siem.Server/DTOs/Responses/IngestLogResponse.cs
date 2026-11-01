// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Responses;

/// <summary>
/// Response returned upon successful ingestion and correlation of a log entry.
/// </summary>
public sealed record IngestLogResponse
{
    public string LogId { get; init; } = string.Empty;
    public string TamperProofHash { get; init; } = string.Empty;
    public string MerkleRoot { get; init; } = string.Empty;
    public int PiiRedacted { get; init; }
    public double RiskScore { get; init; }
    public string SeverityBand { get; init; } = string.Empty;
    public int SigmaMatchesCount { get; init; }
    public DateTimeOffset TimestampUtc { get; init; }
}
