// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Responses;

/// <summary>
/// Overview of active Sigma rule metrics.
/// </summary>
public sealed record SigmaRulesCountResponse
{
    public int ActiveRuleCount { get; init; }
}

/// <summary>
/// Registration confirmation for a new community or custom Sigma rule.
/// </summary>
public sealed record RegisterSigmaRuleResponse
{
    public string Message { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
}
