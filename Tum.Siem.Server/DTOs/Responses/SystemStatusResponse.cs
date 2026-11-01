// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Responses;

/// <summary>
/// Status report of the TUM-OpenSIEM Core engine.
/// </summary>
public sealed record SystemStatusResponse
{
    public string Engine { get; init; } = "TUM-OpenSIEM Sovereign Edition";
    public string Version { get; init; } = "2.0.0-PROD";
    public string Status { get; init; } = "Operational";
    public bool ChainIntact { get; init; }
    public string LastTamperProofHash { get; init; } = string.Empty;
    public string GlobalMerkleRoot { get; init; } = string.Empty;
    public int ActiveSigmaRules { get; init; }
    public string NtpSynchronizedWith { get; init; } = string.Empty;
    public int WormRetentionDays { get; init; }
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;
}
