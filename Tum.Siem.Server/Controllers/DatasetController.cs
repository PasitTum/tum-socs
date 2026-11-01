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
public sealed class DatasetController : ControllerBase
{
    private readonly IDatasetIngestionService _datasetService;

    public DatasetController(IDatasetIngestionService datasetService)
    {
        _datasetService = datasetService ?? throw new ArgumentNullException(nameof(datasetService));
    }

    /// <summary>
    /// Lists available authentic security datasets (OpenSSH brute force, CVE exploits, PDPA transactions).
    /// </summary>
    [HttpGet("catalog")]
    [ProducesResponseType(typeof(DatasetCatalogResponse), StatusCodes.Status200OK)]
    public IActionResult GetCatalog()
    {
        var catalog = _datasetService.GetCatalog();
        return Ok(catalog);
    }

    /// <summary>
    /// Ingests authentic security attack datasets into the SIEM pipeline to demonstrate live correlation.
    /// </summary>
    [HttpPost("load")]
    [ProducesResponseType(typeof(DatasetOperationResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> LoadDataset([FromBody] LoadDatasetRequest? request, CancellationToken cancellationToken)
    {
        var result = await _datasetService.LoadDatasetAsync(request ?? new LoadDatasetRequest(), cancellationToken);
        return Ok(result);
    }

    /// <summary>
    /// Purges all test and demonstration telemetry, resetting storage and Merkle seals to pristine state for customer delivery.
    /// </summary>
    [HttpPost("purge")]
    [ProducesResponseType(typeof(DatasetOperationResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> PurgeForProduction(CancellationToken cancellationToken)
    {
        var result = await _datasetService.PurgeAllDataAsync(cancellationToken);
        return Ok(result);
    }
}
