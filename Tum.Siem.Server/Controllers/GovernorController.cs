// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.Services;

namespace Tum.Siem.Server.Controllers;

public sealed record ConfigureGovernorRequest
{
    public bool? ForceSurge { get; init; }
    public int? SurgeThresholdEps { get; init; }
    public int? BenignSampleRate { get; init; }
}

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class GovernorController : ControllerBase
{
    private readonly ISmartSamplingGovernor _governor;

    public GovernorController(ISmartSamplingGovernor governor)
    {
        _governor = governor ?? throw new ArgumentNullException(nameof(governor));
    }

    /// <summary>
    /// Gets real-time telemetry metrics and surge state of the Smart Sampling Governor.
    /// </summary>
    [HttpGet("status")]
    [ProducesResponseType(typeof(GovernorStats), StatusCodes.Status200OK)]
    public IActionResult GetStatus()
    {
        var stats = _governor.GetStats();
        return Ok(stats);
    }

    /// <summary>
    /// Updates configuration or activates manual surge mitigation mode.
    /// </summary>
    [HttpPost("configure")]
    [ProducesResponseType(typeof(GovernorStats), StatusCodes.Status200OK)]
    public IActionResult Configure([FromBody] ConfigureGovernorRequest request)
    {
        request ??= new ConfigureGovernorRequest();
        _governor.Configure(request.ForceSurge, request.SurgeThresholdEps, request.BenignSampleRate);
        return Ok(_governor.GetStats());
    }
}
