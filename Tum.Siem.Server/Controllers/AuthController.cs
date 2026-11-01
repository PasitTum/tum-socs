// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Siem.Server.Services;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
    }

    /// <summary>
    /// Authenticates user credentials and issues a cryptographic session bearer token.
    /// </summary>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Login([FromBody] LoginRequest? request)
    {
        if (request == null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Authentication Required",
                Detail = "Username and password must be provided.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        var response = _authService.Authenticate(request);
        if (response == null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Authentication Failed",
                Detail = "Invalid username or password credentials provided.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Ok(response);
    }

    /// <summary>
    /// Retrieves current authenticated user profile from bearer token.
    /// </summary>
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserProfileDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        string? authHeader = Request.Headers["Authorization"];
        var profile = _authService.ValidateToken(authHeader);

        if (profile == null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Session Expired or Invalid",
                Detail = "A valid Bearer session token is required.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Ok(profile);
    }

    /// <summary>
    /// Terminates current authenticated session.
    /// </summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Logout()
    {
        return Ok(new { message = "Logged out successfully" });
    }
}
