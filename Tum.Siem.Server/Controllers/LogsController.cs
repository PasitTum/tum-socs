// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;
using Tum.Siem.Server.Services;
using Tum.Trust.Security.Core.Interfaces.Logging;
using Tum.Trust.Security.Core.Models.Logging;
using Tum.Trust.Security.Core.Models.Query;

namespace Tum.Siem.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class LogsController : ControllerBase
{
    private readonly IEventIngestionPipeline _pipeline;
    private readonly ITamperProofLogStorage _storage;
    private readonly IEventQueryEngine _queryEngine;

    public LogsController(
        IEventIngestionPipeline pipeline,
        ITamperProofLogStorage storage,
        IEventQueryEngine queryEngine)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _queryEngine = queryEngine ?? throw new ArgumentNullException(nameof(queryEngine));
    }

    /// <summary>
    /// Ingests a raw security telemetry event through WORM chaining, PII sanitization, and Sigma correlation.
    /// </summary>
    [HttpPost("ingest")]
    [ProducesResponseType(typeof(IngestLogResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Ingest([FromBody] TumLogEntry? entry, CancellationToken cancellationToken)
    {
        if (entry == null)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Invalid Payload",
                Detail = "Log entry payload cannot be null.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var result = await _pipeline.IngestAsync(entry, cancellationToken);
        return Ok(result);
    }

    /// <summary>
    /// Executes Lucene / SQL-style structured queries over tamper-proof log storage.
    /// </summary>
    [HttpGet("query")]
    [ProducesResponseType(typeof(EventQueryResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> Query([FromQuery] QueryLogsRequest request)
    {
        request ??= new QueryLogsRequest();
        var entries = await _storage.GetRecentEntriesAsync(500);

        var queryRequest = new EventQueryRequest
        {
            Query = string.IsNullOrWhiteSpace(request.Query) ? "*" : request.Query,
            Limit = request.Limit > 0 ? request.Limit : 100,
            Offset = Math.Max(0, request.Offset)
        };

        var result = _queryEngine.ExecuteQuery(entries, queryRequest);
        return Ok(result);
    }

    /// <summary>
    /// Stream of recent tamper-evident logs for real-time console feeds.
    /// </summary>
    [HttpGet("live")]
    [HttpGet("/api/events/live")]
    [ProducesResponseType(typeof(IReadOnlyList<TumLogEntry>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetLiveFeed([FromQuery] int limit = 30)
    {
        int cappedLimit = Math.Clamp(limit, 1, 200);
        var entries = await _storage.GetRecentEntriesAsync(cappedLimit);
        return Ok(entries);
    }
}
