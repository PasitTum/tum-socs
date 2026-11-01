// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Tum.Log.Core.Models.Ebpf;
using Tum.Siem.Server.Services;

namespace Tum.Siem.Server.Controllers;

/// <summary>
/// REST API controller for kernel eBPF filesystem hook tracing,
/// binary integrity baseline verification, and tampering alert management (Sprint 10).
/// </summary>
[ApiController]
[Route("api/ebpf/files")]
public class FileTracingController : ControllerBase
{
    private readonly IEbpfFileTracingService _tracingService;

    public FileTracingController(IEbpfFileTracingService tracingService)
    {
        _tracingService = tracingService;
    }

    /// <summary>
    /// Gets overall operational statistics of the eBPF filesystem hook monitor.
    /// </summary>
    [HttpGet("status")]
    public ActionResult<EbpfFileStatusResponse> GetStatus()
    {
        var stats = _tracingService.GetMonitorStatistics();
        return Ok(new EbpfFileStatusResponse
        {
            Engine = "TUM-eBPF-FIM",
            Version = "2.0.0",
            Status = "Active",
            Statistics = stats
        });
    }

    /// <summary>
    /// Ingests a raw eBPF filesystem tracepoint event.
    /// </summary>
    [HttpPost("event")]
    public IActionResult IngestTrace([FromBody] EbpfFileTraceRaw rawTrace)
    {
        if (rawTrace == null || string.IsNullOrWhiteSpace(rawTrace.FilePath))
        {
            return BadRequest(new { error = "Valid FilePath is required." });
        }

        var result = _tracingService.IngestTrace(rawTrace);
        if (result == null)
        {
            return BadRequest(new { error = "Unable to process tracepoint event." });
        }

        return Ok(result);
    }

    /// <summary>
    /// Gets recent binary tampering and suspicious filesystem alerts.
    /// </summary>
    [HttpGet("tampering-alerts")]
    public ActionResult<TamperingAlertsResponse> GetTamperingAlerts([FromQuery] int limit = 50)
    {
        var alerts = _tracingService.GetRecentAlerts(Math.Min(100, Math.Max(1, limit)));
        return Ok(new TamperingAlertsResponse
        {
            Total = alerts.Count,
            Alerts = alerts
        });
    }

    /// <summary>
    /// Registers or updates the expected cryptographic baseline SHA-256 for a binary.
    /// </summary>
    [HttpPost("baseline")]
    public ActionResult<RegisterBaselineResponse> RegisterBaseline([FromBody] RegisterBaselineRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.FilePath) || string.IsNullOrWhiteSpace(request.ExpectedSha256))
        {
            return BadRequest(new { error = "FilePath and ExpectedSha256 are required." });
        }

        _tracingService.RegisterBaseline(request.FilePath, request.ExpectedSha256);
        return Ok(new RegisterBaselineResponse
        {
            Message = "Baseline successfully registered.",
            FilePath = request.FilePath,
            ExpectedSha256 = request.ExpectedSha256.ToLowerInvariant()
        });
    }

    /// <summary>
    /// Simulates a binary tampering attack or anti-forensics log wipe to demonstrate detection capabilities.
    /// </summary>
    [HttpPost("simulate-tampering")]
    public ActionResult<SimulateTamperResponse> SimulateTampering([FromBody] SimulateTamperRequest? request)
    {
        EbpfFileEvent result;
        if (request?.AttackType?.Equals("LogWipe", StringComparison.OrdinalIgnoreCase) == true)
        {
            result = _tracingService.SimulateLogWipeAttempt(request.TargetPath, request.AttackerProcess);
        }
        else
        {
            result = _tracingService.SimulateBinaryTampering(request?.TargetPath, request?.AttackerProcess);
        }

        return Ok(new SimulateTamperResponse
        {
            Message = "Simulation trace successfully processed by kernel hook monitor.",
            Alert = result
        });
    }
}

public class EbpfFileStatusResponse
{
    public string Engine { get; set; } = "TUM-eBPF-FIM";
    public string Version { get; set; } = "2.0.0";
    public string Status { get; set; } = "Active";
    public EbpfFileMonitorStats? Statistics { get; set; }
}

public class TamperingAlertsResponse
{
    public int Total { get; set; }
    public IReadOnlyList<EbpfFileEvent> Alerts { get; set; } = Array.Empty<EbpfFileEvent>();
}

public class RegisterBaselineRequest
{
    public string FilePath { get; set; } = string.Empty;
    public string ExpectedSha256 { get; set; } = string.Empty;
}

public class RegisterBaselineResponse
{
    public string Message { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string ExpectedSha256 { get; set; } = string.Empty;
}

public class SimulateTamperRequest
{
    public string? AttackType { get; set; } = "BinaryModification";
    public string? TargetPath { get; set; }
    public string? AttackerProcess { get; set; }
}

public class SimulateTamperResponse
{
    public string Message { get; set; } = string.Empty;
    public EbpfFileEvent? Alert { get; set; }
}
