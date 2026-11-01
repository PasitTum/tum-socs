// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Siem.Server.Services;
using Tum.Trust.Security.Core.Interfaces.Logging;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class SigmaController : ControllerBase
{
    private readonly ISigmaRuleEngine _sigmaEngine;
    private readonly ISigmaRuleLoaderService _ruleLoader;

    public SigmaController(
        ISigmaRuleEngine sigmaEngine,
        ISigmaRuleLoaderService ruleLoader)
    {
        _sigmaEngine = sigmaEngine ?? throw new ArgumentNullException(nameof(sigmaEngine));
        _ruleLoader = ruleLoader ?? throw new ArgumentNullException(nameof(ruleLoader));
    }

    /// <summary>
    /// Gets metrics regarding currently loaded and active SigmaHQ detection rules.
    /// </summary>
    [HttpGet("rules")]
    [ProducesResponseType(typeof(SigmaRulesCountResponse), StatusCodes.Status200OK)]
    public IActionResult GetRulesSummary()
    {
        return Ok(new SigmaRulesCountResponse
        {
            ActiveRuleCount = _sigmaEngine.ActiveRuleCount
        });
    }

    /// <summary>
    /// Compiles and hot-registers a community Sigma rule from raw YAML content.
    /// </summary>
    [HttpPost("rules")]
    [Consumes("text/plain", "application/x-yaml", "application/json")]
    [ProducesResponseType(typeof(RegisterSigmaRuleResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RegisterRule()
    {
        using var reader = new StreamReader(Request.Body);
        string yaml = await reader.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(yaml))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Missing Rule Body",
                Detail = "A valid YAML rule definition is required in the request body.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        try
        {
            var rule = _ruleLoader.RegisterFromYaml(yaml);
            return Ok(new RegisterSigmaRuleResponse
            {
                Message = "Rule registered and compiled successfully",
                RuleId = rule.Id,
                Title = rule.Title
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Sigma Compilation Error",
                Detail = ex.Message,
                Status = StatusCodes.Status400BadRequest
            });
        }
    }
}
