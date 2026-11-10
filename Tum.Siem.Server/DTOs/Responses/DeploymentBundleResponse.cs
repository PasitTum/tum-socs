// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.DTOs.Requests;

namespace Tum.Siem.Server.DTOs.Responses;

public sealed record DeploymentFileDto
{
    public string Path { get; init; } = string.Empty;
    public string Language { get; init; } = "yaml"; // yaml, shell, sql, ini, markdown
    public string Description { get; init; } = string.Empty;
    public string Content { get; init; } = string.Empty;
}

public sealed record HardwareRecommendationDto
{
    public string MinCpu { get; init; } = string.Empty;
    public string MinRam { get; init; } = string.Empty;
    public string StorageType { get; init; } = string.Empty;
    public string NetworkBandwidth { get; init; } = string.Empty;
    public string MaxSustainedEps { get; init; } = string.Empty;
    public string PeakConcurrencyUsers { get; init; } = string.Empty;
}

public sealed record DeploymentBundleResponse
{
    public ArchitectureTier Tier { get; init; }
    public string TierName { get; init; } = string.Empty;
    public string TargetScenario { get; init; } = string.Empty;
    public HardwareRecommendationDto Hardware { get; init; } = new();
    public IReadOnlyList<DeploymentFileDto> Files { get; init; } = Array.Empty<DeploymentFileDto>();
    public string QuickStartCommand { get; init; } = string.Empty;
    public string OneLineInstallScript { get; init; } = string.Empty;
}
