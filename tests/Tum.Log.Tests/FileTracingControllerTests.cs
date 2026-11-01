// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Tum.Log.Core.Models.Ebpf;
using Tum.Log.Infrastructure.Ebpf;
using Tum.Siem.Server.Controllers;
using Tum.Siem.Server.Services;
using Xunit;

namespace Tum.Log.Tests;

public class FileTracingControllerTests
{
    private readonly FileTracingController _controller;
    private readonly EbpfFileHookMonitor _monitor;

    public FileTracingControllerTests()
    {
        _monitor = new EbpfFileHookMonitor();
        var service = new EbpfFileTracingService(_monitor, NullLogger<EbpfFileTracingService>.Instance);
        _controller = new FileTracingController(service);
    }

    [Fact]
    public void GetStatus_ReturnsOkWithOperationalMetrics()
    {
        var actionResult = _controller.GetStatus();
        var okResult = Assert.IsType<OkObjectResult>(actionResult.Result);
        var response = Assert.IsType<EbpfFileStatusResponse>(okResult.Value);

        Assert.Equal("TUM-eBPF-FIM", response.Engine);
        Assert.Equal("Active", response.Status);
        Assert.NotNull(response.Statistics);
    }

    [Fact]
    public void IngestTrace_ValidTrace_ReturnsOkWithFileEvent()
    {
        var trace = new EbpfFileTraceRaw
        {
            Pid = 1234,
            Uid = 0,
            ProcessName = "update_service",
            FilePath = "/var/log/app.log",
            Syscall = EbpfFileSyscall.Write,
            Timestamp = DateTime.UtcNow
        };

        var actionResult = _controller.IngestTrace(trace);
        var okResult = Assert.IsType<OkObjectResult>(actionResult);
        var ev = Assert.IsType<EbpfFileEvent>(okResult.Value);
        Assert.Equal("/var/log/app.log", ev.FilePath);
        Assert.Equal(1234, ev.ProcessId);
    }

    [Fact]
    public void IngestTrace_NullOrEmptyFilePath_ReturnsBadRequest()
    {
        var trace = new EbpfFileTraceRaw { FilePath = "" };
        var actionResult = _controller.IngestTrace(trace);
        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public void RegisterBaseline_ValidRequest_RegistersHashSuccessfully()
    {
        var request = new RegisterBaselineRequest
        {
            FilePath = "/opt/agent/runner.exe",
            ExpectedSha256 = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"
        };

        var actionResult = _controller.RegisterBaseline(request);
        var okResult = Assert.IsType<OkObjectResult>(actionResult.Result);
        var response = Assert.IsType<RegisterBaselineResponse>(okResult.Value);
        Assert.Equal("/opt/agent/runner.exe", response.FilePath);

        // Verify baseline is reflected in monitor
        string? storedHash = _monitor.GetBinaryBaseline("/opt/agent/runner.exe");
        Assert.Equal(request.ExpectedSha256.ToLowerInvariant(), storedHash);
    }

    [Fact]
    public void SimulateTampering_BinaryModification_ReturnsCriticalThreatAlert()
    {
        var request = new SimulateTamperRequest
        {
            AttackType = "BinaryModification",
            TargetPath = "/usr/bin/sudo",
            AttackerProcess = "apt_simulator.bin"
        };

        var actionResult = _controller.SimulateTampering(request);
        var okResult = Assert.IsType<OkObjectResult>(actionResult.Result);
        var response = Assert.IsType<SimulateTamperResponse>(okResult.Value);
        var alert = response.Alert;

        Assert.NotNull(alert);
        Assert.True(alert!.IsTampering);
        Assert.Equal("Critical", alert.Severity);
        Assert.Equal("T1565.001", alert.MitreTechniqueId);
    }

    [Fact]
    public void SimulateTampering_LogWipe_ReturnsCriticalAntiForensicAlert()
    {
        var request = new SimulateTamperRequest
        {
            AttackType = "LogWipe",
            TargetPath = "/var/log/tum-siem/tamper_ledger.jsonl",
            AttackerProcess = "wiper_daemon"
        };

        var actionResult = _controller.SimulateTampering(request);
        var okResult = Assert.IsType<OkObjectResult>(actionResult.Result);
        var response = Assert.IsType<SimulateTamperResponse>(okResult.Value);
        var alert = response.Alert;

        Assert.NotNull(alert);
        Assert.True(alert!.IsTampering);
        Assert.Equal("Critical", alert.Severity);
        Assert.Equal("T1070.004", alert.MitreTechniqueId);
    }

    [Fact]
    public void GetTamperingAlerts_ReturnsRecentAlertList()
    {
        // Generate an alert first via simulation
        _controller.SimulateTampering(new SimulateTamperRequest());

        var actionResult = _controller.GetTamperingAlerts(10);
        var okResult = Assert.IsType<OkObjectResult>(actionResult.Result);
        var response = Assert.IsType<TamperingAlertsResponse>(okResult.Value);
        Assert.True(response.Total >= 1);
    }
}
