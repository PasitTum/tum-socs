// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Service contract for sovereign user authentication and session lifecycle.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Authenticates credentials and issues a cryptographic session token.
    /// </summary>
    LoginResponse? Authenticate(LoginRequest request);

    /// <summary>
    /// Validates an incoming bearer token and extracts user profile.
    /// </summary>
    UserProfileDto? ValidateToken(string? token);
}
