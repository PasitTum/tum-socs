// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Responses;

public sealed record DatasetItemInfo
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string[] MitreTechniques { get; init; } = Array.Empty<string>();
    public int RecordCount { get; init; }
}

public sealed record DatasetCatalogResponse
{
    public List<DatasetItemInfo> Datasets { get; init; } = new();
    public int TotalAvailableRecords { get; init; }
}

public sealed record DatasetOperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public int IngestedCount { get; init; }
    public int ThreatMatchesCount { get; init; }
    public int PiiRedactedCount { get; init; }
    public string GlobalMerkleRoot { get; init; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;
}
