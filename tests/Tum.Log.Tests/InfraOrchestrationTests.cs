// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Tum.Siem.Server.Controllers;
using Tum.Siem.Server.Models;
using Tum.Siem.Server.Services;
using Xunit;

namespace Tum.Trust.Security.Tests;

public class InfraOrchestrationTests
{
    private readonly HostTelemetryService _telemetry = new();
    private readonly InfraOrchestratorService _orchestrator = new();
    private readonly LoadTestHarnessService _loadTest = new();

    [Fact]
    public void HostTelemetryService_Should_Gather_Authentic_Local_Host_Metrics()
    {
        var local = _telemetry.GetLocalHostMetrics();

        Assert.NotNull(local);
        Assert.Equal("local-master-node", local.NodeId);
        Assert.Equal(Environment.MachineName, local.Hostname);
        Assert.True(local.CpuCoreCount > 0);
        Assert.True(local.TotalMemoryBytes > 0);
        Assert.True(local.UsedMemoryBytes > 0);
        Assert.NotEmpty(local.Disks);
        Assert.True(local.TcpListenCount >= 0);
    }

    [Fact]
    public void HostTelemetryService_Should_Register_And_Retrieve_Remote_Nodes()
    {
        var remote = new HostNodeMetrics
        {
            NodeId = "worker-node-02",
            Hostname = "siem-worker-02.tum.internal",
            IpAddress = "10.0.1.25",
            CpuCoreCount = 16,
            CpuUsagePercent = 28.5,
            TotalMemoryBytes = 64L * 1024 * 1024 * 1024,
            UsedMemoryBytes = 18L * 1024 * 1024 * 1024
        };

        _telemetry.RegisterOrUpdateNode(remote);

        var nodes = _telemetry.GetAllNodes();
        Assert.Contains(nodes, n => n.NodeId == "worker-node-02");
    }

    [Fact]
    public async Task InfraOrchestratorService_Should_Scale_Kubernetes_Deployment()
    {
        var request = new CloudScaleRequest
        {
            Provider = CloudProviderType.Kubernetes,
            Namespace = "security",
            TargetDeploymentName = "tum-opensiem",
            DesiredReplicas = 8
        };

        var result = await _orchestrator.ScaleAsync(request);

        Assert.True(result.Success);
        Assert.Equal(CloudProviderType.Kubernetes, result.Provider);
        Assert.Equal(8, result.CurrentReplicas);
        Assert.Equal("[KUBERNETES_API_ORCHESTRATOR]", result.ProviderAttribution);
    }

    [Fact]
    public async Task InfraOrchestratorService_Should_Reject_Unconfigured_Aws_Credentials_Per_EI_VS()
    {
        // When AWS credentials are not set, must NOT fake a live EC2 creation
        var request = new CloudScaleRequest
        {
            Provider = CloudProviderType.AwsEc2,
            DesiredReplicas = 2,
            InstanceType = "c6i.2xlarge"
        };

        var result = await _orchestrator.ScaleAsync(request);

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")))
        {
            Assert.False(result.Success);
            Assert.Equal("[OFFLINE_UNCONFIGURED_CREDENTIALS]", result.ProviderAttribution);
        }
    }

    [Fact]
    public async Task InfraOrchestratorService_Should_Execute_Benign_Host_Command()
    {
        string cmd = OperatingSystem.IsWindows() ? "echo SIEM_ONLINE" : "echo SIEM_ONLINE";
        var request = new HostCommandRequest
        {
            NodeId = "local-master-node",
            Command = cmd
        };

        var result = await _orchestrator.ExecuteHostCommandAsync(request);

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("SIEM_ONLINE", result.StandardOutput);
    }

    [Fact]
    public async Task InfraOrchestratorService_Should_Block_Destructive_Command_Via_Sentinel()
    {
        var request = new HostCommandRequest
        {
            NodeId = "local-master-node",
            Command = "rm -rf / --no-preserve-root"
        };

        var result = await _orchestrator.ExecuteHostCommandAsync(request);

        Assert.False(result.Success);
        Assert.Contains("BLOCKED by Sovereign Sentinel", result.StandardError);
    }

    [Fact]
    public async Task LoadTestHarness_Should_Execute_Stress_Test_And_Compute_Percentiles()
    {
        var scenario = new LoadTestScenario
        {
            TargetEps = 5_000,
            DurationSeconds = 2,
            RampUpSeconds = 1
        };

        var result = await _loadTest.RunStressTestAsync(scenario);

        Assert.NotNull(result);
        Assert.True(result.TotalEventsSent > 0);
        Assert.True(result.AverageEps > 0);
        Assert.True(result.LatencyP50Ms >= 0);
        Assert.True(result.LatencyP99Ms >= result.LatencyP50Ms);

        // Generate Certificate
        var cert = _loadTest.GenerateReadinessCertificate(result);
        Assert.NotNull(cert);
        Assert.StartsWith("TUM-IRC-", cert.CertificateId);
        Assert.NotEmpty(cert.CryptographicAttestationHash);
        Assert.True(cert.EstimatedConcurrentCapacity > 0);
    }

    [Fact]
    public void InfraController_Endpoints_Should_Return_Expected_Responses()
    {
        var controller = new InfraController(_telemetry, _orchestrator, _loadTest);

        var nodesResult = controller.GetNodes();
        var nodesOk = Assert.IsType<OkObjectResult>(nodesResult);
        Assert.NotNull(nodesOk.Value);

        var certResult = controller.GenerateCertificate(null);
        var certOk = Assert.IsType<OkObjectResult>(certResult);
        var cert = Assert.IsType<InfraReadinessCertificate>(certOk.Value);
        Assert.NotEmpty(cert.CertificateId);
    }
}
