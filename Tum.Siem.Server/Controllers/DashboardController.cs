// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Dashboard;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class DashboardController : ControllerBase
{
    private readonly IThreatAnalyticsEngine _analytics;

    public DashboardController(IThreatAnalyticsEngine analytics)
    {
        _analytics = analytics ?? throw new ArgumentNullException(nameof(analytics));
    }

    /// <summary>
    /// Retrieves real-time high-level threat metrics, alerts breakdown, and EPS rate.
    /// </summary>
    [HttpGet("summary")]
    [ProducesResponseType(typeof(ThreatDashboardSummary), StatusCodes.Status200OK)]
    public IActionResult GetSummary()
    {
        var summary = _analytics.GetDashboardSummary();
        return Ok(summary);
    }

    /// <summary>
    /// Generates correlated attack graph topology nodes and relationship edges.
    /// </summary>
    /// <param name="limit">Max correlated nodes to fetch.</param>
    [HttpGet("attack-graph")]
    [ProducesResponseType(typeof(AttackGraphData), StatusCodes.Status200OK)]
    public IActionResult GetAttackGraph([FromQuery] int? limit)
    {
        var graph = _analytics.GetAttackGraph(limit ?? 50);
        return Ok(graph);
    }

    /// <summary>
    /// Generates cryptographic compliance audit report conforming to Thai CCA Section 26 and ISO 27001.
    /// </summary>
    [HttpGet("compliance")]
    [ProducesResponseType(typeof(ComplianceAuditSummary), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetComplianceReport()
    {
        var report = await _analytics.GenerateComplianceAuditAsync();
        return Ok(report);
    }
}
