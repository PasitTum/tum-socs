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
public sealed class DeploymentController : ControllerBase
{
    private readonly IDeploymentGeneratorService _generator;

    public DeploymentController(IDeploymentGeneratorService generator)
    {
        _generator = generator ?? throw new ArgumentNullException(nameof(generator));
    }

    /// <summary>
    /// Generates tailored Docker Compose, Helm charts, and KEDA autoscaling manifests for the selected traffic tier.
    /// </summary>
    [HttpPost("generate")]
    [ProducesResponseType(typeof(DeploymentBundleResponse), StatusCodes.Status200OK)]
    public IActionResult Generate([FromBody] DeploymentConfigDto? config)
    {
        config ??= new DeploymentConfigDto();
        var bundle = _generator.GenerateBundle(config);
        return Ok(bundle);
    }

    /// <summary>
    /// Downloads the complete deployment configuration package as a ready-to-unzip archive.
    /// </summary>
    [HttpPost("download")]
    [Produces("application/zip")]
    [ProducesResponseType(typeof(FileContentResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> Download([FromBody] DeploymentConfigDto? config)
    {
        config ??= new DeploymentConfigDto();
        byte[] zipBytes = await _generator.GenerateZipArchiveAsync(config);
        string filename = $"tum-opensiem-deployment-{config.Tier.ToString().ToLowerInvariant()}.zip";

        return File(zipBytes, "application/zip", filename);
    }

    /// <summary>
    /// Retrieves architectural presets and capabilities across deployment tiers.
    /// </summary>
    [HttpGet("presets")]
    public IActionResult GetPresets()
    {
        var tiers = new[]
        {
            new
            {
                Tier = ArchitectureTier.SingleNodeLab,
                Name = "Single-Node Lab (< 5,000 EPS)",
                Description = "Lightweight all-in-one container appliance with OpenSIEM and ClickHouse. Ideal for branch offices and staging.",
                DefaultCores = 4,
                DefaultRamGb = 8
            },
            new
            {
                Tier = ArchitectureTier.EnterpriseCluster,
                Name = "Enterprise Clustered Mesh (5,000 - 50,000 EPS)",
                Description = "Clustered deployment with Redpanda streaming buffer, parallel worker containers, ClickHouse, and Redis.",
                DefaultCores = 16,
                DefaultRamGb = 32
            },
            new
            {
                Tier = ArchitectureTier.NationalFlashCrowd,
                Name = "National Scale & Flash Crowd (> 100,000 EPS)",
                Description = "Kubernetes Helm deployment with KEDA event-driven autoscaling, Nginx ingress buffer, and Smart In-Line Sampling. Designed for OCSC / ก.พ. 100k-300k rushes.",
                DefaultCores = 64,
                DefaultRamGb = 128
            }
        };

        return Ok(tiers);
    }
}
