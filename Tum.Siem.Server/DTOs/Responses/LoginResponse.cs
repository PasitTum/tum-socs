// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Siem.Server.DTOs.Responses;

/// <summary>
/// Authenticated user identity metadata.
/// </summary>
public sealed record UserProfileDto
{
    public string Username { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public string Role { get; init; } = string.Empty; // Administrator, SOCAnalyst, ComplianceAuditor
    public string Department { get; init; } = string.Empty;
}

/// <summary>
/// Authentication outcome containing access token and user identity.
/// </summary>
public sealed record LoginResponse
{
    public string Token { get; init; } = string.Empty;
    public string TokenType { get; init; } = "Bearer";
    public int ExpiresInSeconds { get; init; } = 86400;
    public UserProfileDto User { get; init; } = new();
}
